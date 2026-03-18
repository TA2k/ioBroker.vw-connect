.class public abstract Llp/dd;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;Ls71/h;Z)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;
    .locals 17

    .line 1
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->getDriveReadinessRequestMode()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DriveReadinessRequestModePPE;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DriveReadinessRequestModePPE;->POWER_OFF:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/DriveReadinessRequestModePPE;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    const/4 v3, 0x1

    .line 9
    if-ne v0, v1, :cond_0

    .line 10
    .line 11
    move v0, v3

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    move v0, v2

    .line 14
    :goto_0
    invoke-virtual/range {p1 .. p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->getHasOpenDoorsOrFlaps$remoteparkassistcoremeb_release()Z

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 19
    .line 20
    .line 21
    move-result-object v6

    .line 22
    invoke-virtual/range {p1 .. p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isVehicleLocked$remoteparkassistcoremeb_release()Z

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    xor-int/2addr v1, v3

    .line 27
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 28
    .line 29
    .line 30
    move-result-object v7

    .line 31
    invoke-virtual/range {p1 .. p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isHavingDoorsError$remoteparkassistcoremeb_release()Z

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    if-ne v1, v3, :cond_1

    .line 36
    .line 37
    move v12, v3

    .line 38
    goto :goto_1

    .line 39
    :cond_1
    move v12, v2

    .line 40
    :goto_1
    invoke-virtual/range {p0 .. p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->getStandStillStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;

    .line 41
    .line 42
    .line 43
    move-result-object v1

    .line 44
    if-eqz v1, :cond_2

    .line 45
    .line 46
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;->getVmm_EPB()Z

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 51
    .line 52
    .line 53
    move-result-object v1

    .line 54
    :goto_2
    move-object v8, v1

    .line 55
    goto :goto_3

    .line 56
    :cond_2
    const/4 v1, 0x0

    .line 57
    goto :goto_2

    .line 58
    :goto_3
    invoke-virtual/range {p1 .. p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->getHasOpenWindows$remoteparkassistcoremeb_release()Z

    .line 59
    .line 60
    .line 61
    move-result v1

    .line 62
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 63
    .line 64
    .line 65
    move-result-object v9

    .line 66
    invoke-virtual/range {p1 .. p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isComfortClosingPossible()Z

    .line 67
    .line 68
    .line 69
    move-result v1

    .line 70
    if-ne v1, v3, :cond_3

    .line 71
    .line 72
    move v13, v3

    .line 73
    goto :goto_4

    .line 74
    :cond_3
    move v13, v2

    .line 75
    :goto_4
    invoke-virtual/range {p1 .. p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isSafeLockActive$remoteparkassistcoremeb_release()Z

    .line 76
    .line 77
    .line 78
    move-result v1

    .line 79
    if-ne v1, v3, :cond_4

    .line 80
    .line 81
    move/from16 v16, v3

    .line 82
    .line 83
    goto :goto_5

    .line 84
    :cond_4
    move/from16 v16, v2

    .line 85
    .line 86
    :goto_5
    invoke-virtual/range {p1 .. p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->getAcPlugUnlocking()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;

    .line 87
    .line 88
    .line 89
    move-result-object v1

    .line 90
    sget-object v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;->ON:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/HVLMStatusPPE;

    .line 91
    .line 92
    if-ne v1, v4, :cond_5

    .line 93
    .line 94
    move v14, v3

    .line 95
    goto :goto_6

    .line 96
    :cond_5
    move v14, v2

    .line 97
    :goto_6
    invoke-virtual/range {p1 .. p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->isSunroofAvailable$remoteparkassistcoremeb_release()Z

    .line 98
    .line 99
    .line 100
    move-result v1

    .line 101
    if-ne v1, v3, :cond_6

    .line 102
    .line 103
    move v15, v3

    .line 104
    goto :goto_7

    .line 105
    :cond_6
    move v15, v2

    .line 106
    :goto_7
    new-instance v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;

    .line 107
    .line 108
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 109
    .line 110
    .line 111
    move-result-object v5

    .line 112
    move-object/from16 v10, p2

    .line 113
    .line 114
    move/from16 v11, p3

    .line 115
    .line 116
    invoke-direct/range {v4 .. v16}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;-><init>(Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;Ls71/h;ZZZZZZ)V

    .line 117
    .line 118
    .line 119
    return-object v4
.end method

.method public static final b(Ll70/a0;)Ljava/util/List;
    .locals 6

    .line 1
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    if-eqz p0, :cond_4

    .line 6
    .line 7
    const/4 v0, 0x1

    .line 8
    if-eq p0, v0, :cond_3

    .line 9
    .line 10
    const/4 v0, 0x2

    .line 11
    if-eq p0, v0, :cond_2

    .line 12
    .line 13
    const/4 v0, 0x3

    .line 14
    if-eq p0, v0, :cond_1

    .line 15
    .line 16
    const/4 v0, 0x4

    .line 17
    if-ne p0, v0, :cond_0

    .line 18
    .line 19
    sget-object p0, Ll70/q;->k:Ll70/q;

    .line 20
    .line 21
    sget-object v0, Ll70/q;->l:Ll70/q;

    .line 22
    .line 23
    sget-object v1, Ll70/q;->m:Ll70/q;

    .line 24
    .line 25
    filled-new-array {p0, v0, v1}, [Ll70/q;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    invoke-static {p0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    goto :goto_0

    .line 34
    :cond_0
    new-instance p0, La8/r0;

    .line 35
    .line 36
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 37
    .line 38
    .line 39
    throw p0

    .line 40
    :cond_1
    sget-object v0, Ll70/q;->k:Ll70/q;

    .line 41
    .line 42
    sget-object v1, Ll70/q;->l:Ll70/q;

    .line 43
    .line 44
    sget-object v2, Ll70/q;->m:Ll70/q;

    .line 45
    .line 46
    sget-object v3, Ll70/q;->i:Ll70/q;

    .line 47
    .line 48
    sget-object v4, Ll70/q;->j:Ll70/q;

    .line 49
    .line 50
    sget-object v5, Ll70/q;->e:Ll70/q;

    .line 51
    .line 52
    filled-new-array/range {v0 .. v5}, [Ll70/q;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    invoke-static {p0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    goto :goto_0

    .line 61
    :cond_2
    sget-object v0, Ll70/q;->k:Ll70/q;

    .line 62
    .line 63
    sget-object v1, Ll70/q;->l:Ll70/q;

    .line 64
    .line 65
    sget-object v2, Ll70/q;->m:Ll70/q;

    .line 66
    .line 67
    sget-object v3, Ll70/q;->i:Ll70/q;

    .line 68
    .line 69
    sget-object v4, Ll70/q;->h:Ll70/q;

    .line 70
    .line 71
    sget-object v5, Ll70/q;->f:Ll70/q;

    .line 72
    .line 73
    filled-new-array/range {v0 .. v5}, [Ll70/q;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    invoke-static {p0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    goto :goto_0

    .line 82
    :cond_3
    sget-object p0, Ll70/q;->k:Ll70/q;

    .line 83
    .line 84
    sget-object v0, Ll70/q;->l:Ll70/q;

    .line 85
    .line 86
    sget-object v1, Ll70/q;->m:Ll70/q;

    .line 87
    .line 88
    sget-object v2, Ll70/q;->i:Ll70/q;

    .line 89
    .line 90
    sget-object v3, Ll70/q;->d:Ll70/q;

    .line 91
    .line 92
    filled-new-array {p0, v0, v1, v2, v3}, [Ll70/q;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    invoke-static {p0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 97
    .line 98
    .line 99
    move-result-object p0

    .line 100
    goto :goto_0

    .line 101
    :cond_4
    sget-object p0, Ll70/q;->k:Ll70/q;

    .line 102
    .line 103
    sget-object v0, Ll70/q;->l:Ll70/q;

    .line 104
    .line 105
    sget-object v1, Ll70/q;->m:Ll70/q;

    .line 106
    .line 107
    sget-object v2, Ll70/q;->j:Ll70/q;

    .line 108
    .line 109
    sget-object v3, Ll70/q;->g:Ll70/q;

    .line 110
    .line 111
    filled-new-array {p0, v0, v1, v2, v3}, [Ll70/q;

    .line 112
    .line 113
    .line 114
    move-result-object p0

    .line 115
    invoke-static {p0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 116
    .line 117
    .line 118
    move-result-object p0

    .line 119
    :goto_0
    check-cast p0, Ljava/lang/Iterable;

    .line 120
    .line 121
    new-instance v0, La5/f;

    .line 122
    .line 123
    const/16 v1, 0x13

    .line 124
    .line 125
    invoke-direct {v0, v1}, La5/f;-><init>(I)V

    .line 126
    .line 127
    .line 128
    invoke-static {p0, v0}, Lmx0/q;->p0(Ljava/lang/Iterable;Ljava/util/Comparator;)Ljava/util/List;

    .line 129
    .line 130
    .line 131
    move-result-object p0

    .line 132
    return-object p0
.end method
