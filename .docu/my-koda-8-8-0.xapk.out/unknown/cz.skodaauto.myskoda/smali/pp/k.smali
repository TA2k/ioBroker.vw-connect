.class public abstract Lpp/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:[Ljo/d;


# direct methods
.method static constructor <clinit>()V
    .locals 18

    .line 1
    new-instance v0, Ljo/d;

    .line 2
    .line 3
    const-wide/16 v1, 0x1

    .line 4
    .line 5
    const-string v3, "name_ulr_private"

    .line 6
    .line 7
    invoke-direct {v0, v1, v2, v3}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 8
    .line 9
    .line 10
    new-instance v3, Ljo/d;

    .line 11
    .line 12
    const-string v4, "name_sleep_segment_request"

    .line 13
    .line 14
    invoke-direct {v3, v1, v2, v4}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 15
    .line 16
    .line 17
    new-instance v4, Ljo/d;

    .line 18
    .line 19
    const-string v5, "get_last_activity_feature_id"

    .line 20
    .line 21
    invoke-direct {v4, v1, v2, v5}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 22
    .line 23
    .line 24
    move-object v5, v3

    .line 25
    new-instance v3, Ljo/d;

    .line 26
    .line 27
    const-string v6, "support_context_feature_id"

    .line 28
    .line 29
    invoke-direct {v3, v1, v2, v6}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 30
    .line 31
    .line 32
    move-object v6, v4

    .line 33
    new-instance v4, Ljo/d;

    .line 34
    .line 35
    const-string v7, "get_current_location"

    .line 36
    .line 37
    const-wide/16 v8, 0x2

    .line 38
    .line 39
    invoke-direct {v4, v8, v9, v7}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 40
    .line 41
    .line 42
    move-object v7, v5

    .line 43
    new-instance v5, Ljo/d;

    .line 44
    .line 45
    const-string v8, "get_last_location_with_request"

    .line 46
    .line 47
    invoke-direct {v5, v1, v2, v8}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 48
    .line 49
    .line 50
    move-object v8, v6

    .line 51
    new-instance v6, Ljo/d;

    .line 52
    .line 53
    const-string v9, "set_mock_mode_with_callback"

    .line 54
    .line 55
    invoke-direct {v6, v1, v2, v9}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 56
    .line 57
    .line 58
    move-object v9, v7

    .line 59
    new-instance v7, Ljo/d;

    .line 60
    .line 61
    const-string v10, "set_mock_location_with_callback"

    .line 62
    .line 63
    invoke-direct {v7, v1, v2, v10}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 64
    .line 65
    .line 66
    move-object v10, v8

    .line 67
    new-instance v8, Ljo/d;

    .line 68
    .line 69
    const-string v11, "inject_location_with_callback"

    .line 70
    .line 71
    invoke-direct {v8, v1, v2, v11}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 72
    .line 73
    .line 74
    move-object v11, v9

    .line 75
    new-instance v9, Ljo/d;

    .line 76
    .line 77
    const-string v12, "location_updates_with_callback"

    .line 78
    .line 79
    invoke-direct {v9, v1, v2, v12}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 80
    .line 81
    .line 82
    move-object v12, v10

    .line 83
    new-instance v10, Ljo/d;

    .line 84
    .line 85
    const-string v13, "use_safe_parcelable_in_intents"

    .line 86
    .line 87
    invoke-direct {v10, v1, v2, v13}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 88
    .line 89
    .line 90
    move-object v13, v11

    .line 91
    new-instance v11, Ljo/d;

    .line 92
    .line 93
    const-string v14, "flp_debug_updates"

    .line 94
    .line 95
    invoke-direct {v11, v1, v2, v14}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 96
    .line 97
    .line 98
    move-object v14, v12

    .line 99
    new-instance v12, Ljo/d;

    .line 100
    .line 101
    const-string v15, "google_location_accuracy_enabled"

    .line 102
    .line 103
    invoke-direct {v12, v1, v2, v15}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 104
    .line 105
    .line 106
    move-object v15, v13

    .line 107
    new-instance v13, Ljo/d;

    .line 108
    .line 109
    move-object/from16 v16, v0

    .line 110
    .line 111
    const-string v0, "geofences_with_callback"

    .line 112
    .line 113
    invoke-direct {v13, v1, v2, v0}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 114
    .line 115
    .line 116
    move-object v0, v14

    .line 117
    new-instance v14, Ljo/d;

    .line 118
    .line 119
    move-object/from16 v17, v0

    .line 120
    .line 121
    const-string v0, "location_enabled"

    .line 122
    .line 123
    invoke-direct {v14, v1, v2, v0}, Ljo/d;-><init>(JLjava/lang/String;)V

    .line 124
    .line 125
    .line 126
    move-object v1, v15

    .line 127
    move-object/from16 v0, v16

    .line 128
    .line 129
    move-object/from16 v2, v17

    .line 130
    .line 131
    filled-new-array/range {v0 .. v14}, [Ljo/d;

    .line 132
    .line 133
    .line 134
    move-result-object v0

    .line 135
    sput-object v0, Lpp/k;->a:[Ljo/d;

    .line 136
    .line 137
    return-void
.end method

.method public static a(I)V
    .locals 2

    .line 1
    const/16 v0, 0x64

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    if-eq p0, v0, :cond_1

    .line 5
    .line 6
    const/16 v0, 0x66

    .line 7
    .line 8
    if-eq p0, v0, :cond_1

    .line 9
    .line 10
    const/16 v0, 0x68

    .line 11
    .line 12
    if-eq p0, v0, :cond_1

    .line 13
    .line 14
    const/16 v0, 0x69

    .line 15
    .line 16
    if-ne p0, v0, :cond_0

    .line 17
    .line 18
    move p0, v0

    .line 19
    goto :goto_0

    .line 20
    :cond_0
    const/4 v1, 0x0

    .line 21
    :cond_1
    :goto_0
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    const-string v0, "priority %d must be a Priority.PRIORITY_* constant"

    .line 30
    .line 31
    invoke-static {v1, v0, p0}, Lno/c0;->c(ZLjava/lang/String;[Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    return-void
.end method

.method public static b(I)Ljava/lang/String;
    .locals 1

    .line 1
    const/16 v0, 0x64

    .line 2
    .line 3
    if-eq p0, v0, :cond_3

    .line 4
    .line 5
    const/16 v0, 0x66

    .line 6
    .line 7
    if-eq p0, v0, :cond_2

    .line 8
    .line 9
    const/16 v0, 0x68

    .line 10
    .line 11
    if-eq p0, v0, :cond_1

    .line 12
    .line 13
    const/16 v0, 0x69

    .line 14
    .line 15
    if-ne p0, v0, :cond_0

    .line 16
    .line 17
    const-string p0, "PASSIVE"

    .line 18
    .line 19
    return-object p0

    .line 20
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 21
    .line 22
    invoke-direct {p0}, Ljava/lang/IllegalArgumentException;-><init>()V

    .line 23
    .line 24
    .line 25
    throw p0

    .line 26
    :cond_1
    const-string p0, "LOW_POWER"

    .line 27
    .line 28
    return-object p0

    .line 29
    :cond_2
    const-string p0, "BALANCED_POWER_ACCURACY"

    .line 30
    .line 31
    return-object p0

    .line 32
    :cond_3
    const-string p0, "HIGH_ACCURACY"

    .line 33
    .line 34
    return-object p0
.end method
