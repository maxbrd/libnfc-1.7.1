/*-
 * Free/Libre Near Field Communication (NFC) library
 *
 * Libnfc historical contributors:
 * Copyright (C) 2009      Roel Verdult
 * Copyright (C) 2009-2013 Romuald Conty
 * Copyright (C) 2010-2012 Romain Tartière
 * Copyright (C) 2010-2013 Philippe Teuwen
 * Copyright (C) 2012-2013 Ludovic Rousseau
 * See AUTHORS file for a more comprehensive list of contributors.
 * Additional contributors of this file:
 * Copyright (C) 2013      Adam Laurie
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *  1) Redistributions of source code must retain the above copyright notice,
 *  this list of conditions and the following disclaimer.
 *  2 )Redistributions in binary form must reproduce the above copyright
 *  notice, this list of conditions and the following disclaimer in the
 *  documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Note that this license only applies on the examples, NFC library itself is under LGPL
 *
 */

/**
 * @file nfc-mfultralight.c
 * @brief MIFARE Ultralight dump/restore tool
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif // HAVE_CONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <string.h>
#include <ctype.h>

#include <nfc/nfc.h>

#include "nfc-utils.h"
#include "mifare.h"

static nfc_device *pnd;
static nfc_target nt;
static mifare_param mp;
static mifareul_tag mtDump;
static uint32_t uiBlocks = 0xF;

static const nfc_modulation nmMifare = {
  .nmt = NMT_ISO14443A,
  .nbr = NBR_106,
};

static void
print_success_or_failure(bool bFailure, uint32_t *uiCounter)
{
  printf("%c", (bFailure) ? 'x' : '.');
  if (uiCounter)
    *uiCounter += (bFailure) ? 0 : 1;
}

static  bool
read_card(void)
{
  uint32_t page;
  bool    bFailure = false;
  uint32_t uiReadedPages = 0;

  printf("Lecture de %d pages |", uiBlocks + 1);

  for (page = 0; page <= uiBlocks; page += 4) {
    // Try to read out the data block
    if (nfc_initiator_mifare_cmd(pnd, MC_READ, page, &mp)) {
      memcpy(mtDump.amb[page / 4].mbd.abtData, mp.mpd.abtData, 16);
    } else {
      bFailure = true;
      break;
    }

    print_success_or_failure(bFailure, &uiReadedPages);
    print_success_or_failure(bFailure, &uiReadedPages);
    print_success_or_failure(bFailure, &uiReadedPages);
    print_success_or_failure(bFailure, &uiReadedPages);
  }
  printf("|\n");
  printf("Fait, %d pages sur %d lus.\n", uiReadedPages, uiBlocks + 1);
  fflush(stdout);

  return (!bFailure);
}

static  bool
write_card(void)
{
  uint32_t uiBlock = 0;
  bool    bFailure = false;
  uint32_t uiWritenPages = 0;
  uint32_t uiSkippedPages = 0;

  char    buffer[BUFSIZ];
  bool    write_otp;
  bool    write_lock;
  bool    write_uid;

  printf("Write OTP bytes ? [yN] ");
  if (!fgets(buffer, BUFSIZ, stdin)) {
    ERR("Impossible de lire l'entrée standard.");
  }
  write_otp = ((buffer[0] == 'y') || (buffer[0] == 'Y'));
  printf("Write Lock bytes ? [yN] ");
  if (!fgets(buffer, BUFSIZ, stdin)) {
    ERR("Impossible de lire l'entrée standard.");
  }
  write_lock = ((buffer[0] == 'y') || (buffer[0] == 'Y'));
  printf("Write UID bytes (only for special writeable UID cards) ? [yN] ");
  if (!fgets(buffer, BUFSIZ, stdin)) {
    ERR("Impossible de lire l'entrée standard.");
  }
  write_uid = ((buffer[0] == 'y') || (buffer[0] == 'Y'));

  printf("Ecriture de %d pages |", uiBlocks + 1);
  /* We may need to skip 2 first pages. */
  if (!write_uid) {
    printf("ss");
    uiSkippedPages = 2;
  }

  for (int page = uiSkippedPages; page <= 0xF; page++) {
    if ((page == 0x2) && (!write_lock)) {
      printf("s");
      uiSkippedPages++;
      continue;
    }
    if ((page == 0x3) && (!write_otp)) {
      printf("s");
      uiSkippedPages++;
      continue;
    }
    // Show if the readout went well
    if (bFailure) {
      // When a failure occured we need to redo the anti-collision
      if (nfc_initiator_select_passive_target(pnd, nmMifare, NULL, 0, &nt) <= 0) {
        ERR("le tag a été retiré");
        return false;
      }
      bFailure = false;
    }
    // For the Mifare Ultralight, this write command can be used
    // in compatibility mode, which only actually writes the first
    // page (4 bytes). The Ultralight-specific Write command only
    // writes one page at a time.
    uiBlock = page / 4;
    memcpy(mp.mpd.abtData, mtDump.amb[uiBlock].mbd.abtData + ((page % 4) * 4), 16);
    if (!nfc_initiator_mifare_cmd(pnd, MC_WRITE, page, &mp))
      bFailure = true;

    print_success_or_failure(bFailure, &uiWritenPages);
  }
  printf("|\n");
  printf("Fait, %d pages sur %d écrites (%d pages sautées).\n", uiWritenPages, uiBlocks + 1, uiSkippedPages);

  return true;
}

int
main(int argc, const char *argv[])
{
  bool    bReadAction;
  FILE   *pfDump;

  if (argc < 3) {
    printf("\n");
    printf("%s r|w <dump.mfd>\n", argv[0]);
    printf("\n");
    printf("r|w         - Lire ou écrire sur la carte\n");
    printf("<dump.mfd>  - MiFare Dump (MFD) utilisé pour écrire (carte vers MFD) ou (MFD vers la carte)\n");
    printf("\n");
    exit(EXIT_FAILURE);
  }

  DBG("\nVérifier les arguments et les paramètres\n");

  bReadAction = tolower((int)((unsigned char) * (argv[1])) == 'r');

  if (bReadAction) {
    memset(&mtDump, 0x00, sizeof(mtDump));
  } else {
    pfDump = fopen(argv[2], "rb");

    if (pfDump == NULL) {
      ERR("Impossible d'ouvrir le dump: %s\n", argv[2]);
      exit(EXIT_FAILURE);
    }

    if (fread(&mtDump, 1, sizeof(mtDump), pfDump) != sizeof(mtDump)) {
      ERR("Impossible de lire le dump: %s\n", argv[2]);
      fclose(pfDump);
      exit(EXIT_FAILURE);
    }
    fclose(pfDump);
  }
  DBG("Dump ouvert avec succès\n");

  nfc_context *context;
  nfc_init(&context);
  if (context == NULL) {
    ERR("Impossible d'initer libnfc (malloc)");
    exit(EXIT_FAILURE);
  }

  // Try to open the NFC device
  pnd = nfc_open(context, NULL);
  if (pnd == NULL) {
    ERR("Erreur pendant l'ouverture du support NFC");
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }

  if (nfc_initiator_init(pnd) < 0) {
    nfc_perror(pnd, "nfc_initiator_init");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }

  // Let the device only try once to find a tag
  if (nfc_device_set_property_bool(pnd, NP_INFINITE_SELECT, false) < 0) {
    nfc_perror(pnd, "nfc_device_set_property_bool");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }

  printf("Support NFC: %s ouvert\n", nfc_device_get_name(pnd));

  // Try to find a MIFARE Ultralight tag
  if (nfc_initiator_select_passive_target(pnd, nmMifare, NULL, 0, &nt) <= 0) {
    ERR("aucun tag trouvé\n");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }
  // Test if we are dealing with a MIFARE compatible tag

  if (nt.nti.nai.abtAtqa[1] != 0x44) {
    ERR("le tag n'est pas une carte MIFARE Ultralight\n");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }
  // Get the info from the current tag
  printf("Carte MIFARE Ultralight trouvée avec l'UID: ");
  size_t  szPos;
  for (szPos = 0; szPos < nt.nti.nai.szUidLen; szPos++) {
    printf("%02x", nt.nti.nai.abtUid[szPos]);
  }
  printf("\n");

  if (bReadAction) {
    if (read_card()) {
      printf("Ecriture des données dans le fichier: %s ... ", argv[2]);
      fflush(stdout);
      pfDump = fopen(argv[2], "wb");
      if (pfDump == NULL) {
        printf("Impossible d'ouvrir le fichier: %s\n", argv[2]);
        nfc_close(pnd);
        nfc_exit(context);
        exit(EXIT_FAILURE);
      }
      if (fwrite(&mtDump, 1, sizeof(mtDump), pfDump) != sizeof(mtDump)) {
        printf("Impossible d'écrire dans le fichier: %s\n", argv[2]);
        fclose(pfDump);
        nfc_close(pnd);
        nfc_exit(context);
        exit(EXIT_FAILURE);
      }
      fclose(pfDump);
      printf("Fait.\n");
    }
  } else {
    write_card();
  }

  nfc_close(pnd);
  nfc_exit(context);
  exit(EXIT_SUCCESS);
}
