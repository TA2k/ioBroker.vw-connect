.class public final enum Lk01/b;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final e:Lk01/a0;

.field public static final enum f:Lk01/b;

.field public static final enum g:Lk01/b;

.field public static final enum h:Lk01/b;

.field public static final enum i:Lk01/b;

.field public static final enum j:Lk01/b;

.field public static final enum k:Lk01/b;

.field public static final synthetic l:[Lk01/b;


# instance fields
.field public final d:I


# direct methods
.method static constructor <clinit>()V
    .locals 16

    .line 1
    new-instance v0, Lk01/b;

    .line 2
    .line 3
    const-string v1, "NO_ERROR"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2, v2}, Lk01/b;-><init>(Ljava/lang/String;II)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lk01/b;->f:Lk01/b;

    .line 10
    .line 11
    new-instance v1, Lk01/b;

    .line 12
    .line 13
    const-string v2, "PROTOCOL_ERROR"

    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    invoke-direct {v1, v2, v3, v3}, Lk01/b;-><init>(Ljava/lang/String;II)V

    .line 17
    .line 18
    .line 19
    sput-object v1, Lk01/b;->g:Lk01/b;

    .line 20
    .line 21
    new-instance v2, Lk01/b;

    .line 22
    .line 23
    const-string v3, "INTERNAL_ERROR"

    .line 24
    .line 25
    const/4 v4, 0x2

    .line 26
    invoke-direct {v2, v3, v4, v4}, Lk01/b;-><init>(Ljava/lang/String;II)V

    .line 27
    .line 28
    .line 29
    sput-object v2, Lk01/b;->h:Lk01/b;

    .line 30
    .line 31
    new-instance v3, Lk01/b;

    .line 32
    .line 33
    const-string v4, "FLOW_CONTROL_ERROR"

    .line 34
    .line 35
    const/4 v5, 0x3

    .line 36
    invoke-direct {v3, v4, v5, v5}, Lk01/b;-><init>(Ljava/lang/String;II)V

    .line 37
    .line 38
    .line 39
    sput-object v3, Lk01/b;->i:Lk01/b;

    .line 40
    .line 41
    new-instance v4, Lk01/b;

    .line 42
    .line 43
    const-string v5, "SETTINGS_TIMEOUT"

    .line 44
    .line 45
    const/4 v6, 0x4

    .line 46
    invoke-direct {v4, v5, v6, v6}, Lk01/b;-><init>(Ljava/lang/String;II)V

    .line 47
    .line 48
    .line 49
    new-instance v5, Lk01/b;

    .line 50
    .line 51
    const-string v6, "STREAM_CLOSED"

    .line 52
    .line 53
    const/4 v7, 0x5

    .line 54
    invoke-direct {v5, v6, v7, v7}, Lk01/b;-><init>(Ljava/lang/String;II)V

    .line 55
    .line 56
    .line 57
    new-instance v6, Lk01/b;

    .line 58
    .line 59
    const-string v7, "FRAME_SIZE_ERROR"

    .line 60
    .line 61
    const/4 v8, 0x6

    .line 62
    invoke-direct {v6, v7, v8, v8}, Lk01/b;-><init>(Ljava/lang/String;II)V

    .line 63
    .line 64
    .line 65
    new-instance v7, Lk01/b;

    .line 66
    .line 67
    const-string v8, "REFUSED_STREAM"

    .line 68
    .line 69
    const/4 v9, 0x7

    .line 70
    invoke-direct {v7, v8, v9, v9}, Lk01/b;-><init>(Ljava/lang/String;II)V

    .line 71
    .line 72
    .line 73
    sput-object v7, Lk01/b;->j:Lk01/b;

    .line 74
    .line 75
    new-instance v8, Lk01/b;

    .line 76
    .line 77
    const-string v9, "CANCEL"

    .line 78
    .line 79
    const/16 v10, 0x8

    .line 80
    .line 81
    invoke-direct {v8, v9, v10, v10}, Lk01/b;-><init>(Ljava/lang/String;II)V

    .line 82
    .line 83
    .line 84
    sput-object v8, Lk01/b;->k:Lk01/b;

    .line 85
    .line 86
    new-instance v9, Lk01/b;

    .line 87
    .line 88
    const-string v10, "COMPRESSION_ERROR"

    .line 89
    .line 90
    const/16 v11, 0x9

    .line 91
    .line 92
    invoke-direct {v9, v10, v11, v11}, Lk01/b;-><init>(Ljava/lang/String;II)V

    .line 93
    .line 94
    .line 95
    new-instance v10, Lk01/b;

    .line 96
    .line 97
    const-string v11, "CONNECT_ERROR"

    .line 98
    .line 99
    const/16 v12, 0xa

    .line 100
    .line 101
    invoke-direct {v10, v11, v12, v12}, Lk01/b;-><init>(Ljava/lang/String;II)V

    .line 102
    .line 103
    .line 104
    new-instance v11, Lk01/b;

    .line 105
    .line 106
    const-string v12, "ENHANCE_YOUR_CALM"

    .line 107
    .line 108
    const/16 v13, 0xb

    .line 109
    .line 110
    invoke-direct {v11, v12, v13, v13}, Lk01/b;-><init>(Ljava/lang/String;II)V

    .line 111
    .line 112
    .line 113
    new-instance v12, Lk01/b;

    .line 114
    .line 115
    const-string v13, "INADEQUATE_SECURITY"

    .line 116
    .line 117
    const/16 v14, 0xc

    .line 118
    .line 119
    invoke-direct {v12, v13, v14, v14}, Lk01/b;-><init>(Ljava/lang/String;II)V

    .line 120
    .line 121
    .line 122
    new-instance v13, Lk01/b;

    .line 123
    .line 124
    const-string v14, "HTTP_1_1_REQUIRED"

    .line 125
    .line 126
    const/16 v15, 0xd

    .line 127
    .line 128
    invoke-direct {v13, v14, v15, v15}, Lk01/b;-><init>(Ljava/lang/String;II)V

    .line 129
    .line 130
    .line 131
    filled-new-array/range {v0 .. v13}, [Lk01/b;

    .line 132
    .line 133
    .line 134
    move-result-object v0

    .line 135
    sput-object v0, Lk01/b;->l:[Lk01/b;

    .line 136
    .line 137
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 138
    .line 139
    .line 140
    new-instance v0, Lk01/a0;

    .line 141
    .line 142
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 143
    .line 144
    .line 145
    sput-object v0, Lk01/b;->e:Lk01/a0;

    .line 146
    .line 147
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;II)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput p3, p0, Lk01/b;->d:I

    .line 5
    .line 6
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lk01/b;
    .locals 1

    .line 1
    const-class v0, Lk01/b;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lk01/b;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lk01/b;
    .locals 1

    .line 1
    sget-object v0, Lk01/b;->l:[Lk01/b;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lk01/b;

    .line 8
    .line 9
    return-object v0
.end method
