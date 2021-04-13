/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Collections.Generic;
using SMBLibrary.Client;

namespace SMBLibrary.Server
{
    internal class OpenSearch
    {
        public List<FindFilesQueryResult> Entries;
        public int EnumerationLocation;

        public OpenSearch(List<FindFilesQueryResult> entries, int enumerationLocation)
        {
            Entries = entries;
            EnumerationLocation = enumerationLocation;
        }
    }
}
