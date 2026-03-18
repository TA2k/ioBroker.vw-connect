.class public final enum Lzg/g;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lzg/g;",
        ">;"
    }
.end annotation

.annotation runtime Lqz0/g;
.end annotation


# static fields
.field public static final Companion:Lzg/f;

.field public static final d:Ljava/lang/Object;

.field public static final enum e:Lzg/g;

.field public static final enum f:Lzg/g;

.field public static final enum g:Lzg/g;

.field public static final enum h:Lzg/g;

.field public static final enum i:Lzg/g;

.field public static final synthetic j:[Lzg/g;


# direct methods
.method static constructor <clinit>()V
    .locals 11

    .line 1
    new-instance v0, Lzg/g;

    .line 2
    .line 3
    const-string v1, "AVAILABLE"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    new-instance v1, Lzg/g;

    .line 10
    .line 11
    const-string v2, "CHARGING_IN_PROGRESS"

    .line 12
    .line 13
    const/4 v3, 0x1

    .line 14
    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 15
    .line 16
    .line 17
    sput-object v1, Lzg/g;->e:Lzg/g;

    .line 18
    .line 19
    new-instance v2, Lzg/g;

    .line 20
    .line 21
    const-string v3, "CHARGING_NOT_POSSIBLE"

    .line 22
    .line 23
    const/4 v4, 0x2

    .line 24
    invoke-direct {v2, v3, v4}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 25
    .line 26
    .line 27
    sput-object v2, Lzg/g;->f:Lzg/g;

    .line 28
    .line 29
    new-instance v3, Lzg/g;

    .line 30
    .line 31
    const-string v4, "CHARGING_PROCESS_FINISHED"

    .line 32
    .line 33
    const/4 v5, 0x3

    .line 34
    invoke-direct {v3, v4, v5}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 35
    .line 36
    .line 37
    new-instance v4, Lzg/g;

    .line 38
    .line 39
    const-string v5, "PAUSE"

    .line 40
    .line 41
    const/4 v6, 0x4

    .line 42
    invoke-direct {v4, v5, v6}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 43
    .line 44
    .line 45
    sput-object v4, Lzg/g;->g:Lzg/g;

    .line 46
    .line 47
    new-instance v5, Lzg/g;

    .line 48
    .line 49
    const-string v6, "READY_FOR_CHARGING"

    .line 50
    .line 51
    const/4 v7, 0x5

    .line 52
    invoke-direct {v5, v6, v7}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 53
    .line 54
    .line 55
    new-instance v6, Lzg/g;

    .line 56
    .line 57
    const-string v7, "UNKNOWN"

    .line 58
    .line 59
    const/4 v8, 0x6

    .line 60
    invoke-direct {v6, v7, v8}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 61
    .line 62
    .line 63
    sput-object v6, Lzg/g;->h:Lzg/g;

    .line 64
    .line 65
    new-instance v7, Lzg/g;

    .line 66
    .line 67
    const-string v8, "WAITING_FOR_AUTHORIZATION"

    .line 68
    .line 69
    const/4 v9, 0x7

    .line 70
    invoke-direct {v7, v8, v9}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 71
    .line 72
    .line 73
    sput-object v7, Lzg/g;->i:Lzg/g;

    .line 74
    .line 75
    new-instance v8, Lzg/g;

    .line 76
    .line 77
    const-string v9, "WAITING_FOR_CHARGING"

    .line 78
    .line 79
    const/16 v10, 0x8

    .line 80
    .line 81
    invoke-direct {v8, v9, v10}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 82
    .line 83
    .line 84
    filled-new-array/range {v0 .. v8}, [Lzg/g;

    .line 85
    .line 86
    .line 87
    move-result-object v0

    .line 88
    sput-object v0, Lzg/g;->j:[Lzg/g;

    .line 89
    .line 90
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 91
    .line 92
    .line 93
    new-instance v0, Lzg/f;

    .line 94
    .line 95
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 96
    .line 97
    .line 98
    sput-object v0, Lzg/g;->Companion:Lzg/f;

    .line 99
    .line 100
    sget-object v0, Llx0/j;->e:Llx0/j;

    .line 101
    .line 102
    new-instance v1, Lz81/g;

    .line 103
    .line 104
    const/16 v2, 0xe

    .line 105
    .line 106
    invoke-direct {v1, v2}, Lz81/g;-><init>(I)V

    .line 107
    .line 108
    .line 109
    invoke-static {v0, v1}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 110
    .line 111
    .line 112
    move-result-object v0

    .line 113
    sput-object v0, Lzg/g;->d:Ljava/lang/Object;

    .line 114
    .line 115
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lzg/g;
    .locals 1

    .line 1
    const-class v0, Lzg/g;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lzg/g;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lzg/g;
    .locals 1

    .line 1
    sget-object v0, Lzg/g;->j:[Lzg/g;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lzg/g;

    .line 8
    .line 9
    return-object v0
.end method
