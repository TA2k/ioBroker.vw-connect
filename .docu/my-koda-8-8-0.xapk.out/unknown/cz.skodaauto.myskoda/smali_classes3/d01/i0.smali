.class public final enum Ld01/i0;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final e:Ld01/r;

.field public static final enum f:Ld01/i0;

.field public static final enum g:Ld01/i0;

.field public static final enum h:Ld01/i0;

.field public static final enum i:Ld01/i0;

.field public static final enum j:Ld01/i0;

.field public static final enum k:Ld01/i0;

.field public static final enum l:Ld01/i0;

.field public static final synthetic m:[Ld01/i0;


# instance fields
.field public final d:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 10

    .line 1
    new-instance v0, Ld01/i0;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const-string v2, "http/1.0"

    .line 5
    .line 6
    const-string v3, "HTTP_1_0"

    .line 7
    .line 8
    invoke-direct {v0, v3, v1, v2}, Ld01/i0;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 9
    .line 10
    .line 11
    sput-object v0, Ld01/i0;->f:Ld01/i0;

    .line 12
    .line 13
    new-instance v1, Ld01/i0;

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    const-string v3, "http/1.1"

    .line 17
    .line 18
    const-string v4, "HTTP_1_1"

    .line 19
    .line 20
    invoke-direct {v1, v4, v2, v3}, Ld01/i0;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 21
    .line 22
    .line 23
    sput-object v1, Ld01/i0;->g:Ld01/i0;

    .line 24
    .line 25
    new-instance v2, Ld01/i0;

    .line 26
    .line 27
    const/4 v3, 0x2

    .line 28
    const-string v4, "spdy/3.1"

    .line 29
    .line 30
    const-string v5, "SPDY_3"

    .line 31
    .line 32
    invoke-direct {v2, v5, v3, v4}, Ld01/i0;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 33
    .line 34
    .line 35
    sput-object v2, Ld01/i0;->h:Ld01/i0;

    .line 36
    .line 37
    new-instance v3, Ld01/i0;

    .line 38
    .line 39
    const/4 v4, 0x3

    .line 40
    const-string v5, "h2"

    .line 41
    .line 42
    const-string v6, "HTTP_2"

    .line 43
    .line 44
    invoke-direct {v3, v6, v4, v5}, Ld01/i0;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 45
    .line 46
    .line 47
    sput-object v3, Ld01/i0;->i:Ld01/i0;

    .line 48
    .line 49
    new-instance v4, Ld01/i0;

    .line 50
    .line 51
    const/4 v5, 0x4

    .line 52
    const-string v6, "h2_prior_knowledge"

    .line 53
    .line 54
    const-string v7, "H2_PRIOR_KNOWLEDGE"

    .line 55
    .line 56
    invoke-direct {v4, v7, v5, v6}, Ld01/i0;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 57
    .line 58
    .line 59
    sput-object v4, Ld01/i0;->j:Ld01/i0;

    .line 60
    .line 61
    new-instance v5, Ld01/i0;

    .line 62
    .line 63
    const/4 v6, 0x5

    .line 64
    const-string v7, "quic"

    .line 65
    .line 66
    const-string v8, "QUIC"

    .line 67
    .line 68
    invoke-direct {v5, v8, v6, v7}, Ld01/i0;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 69
    .line 70
    .line 71
    sput-object v5, Ld01/i0;->k:Ld01/i0;

    .line 72
    .line 73
    new-instance v6, Ld01/i0;

    .line 74
    .line 75
    const/4 v7, 0x6

    .line 76
    const-string v8, "h3"

    .line 77
    .line 78
    const-string v9, "HTTP_3"

    .line 79
    .line 80
    invoke-direct {v6, v9, v7, v8}, Ld01/i0;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 81
    .line 82
    .line 83
    sput-object v6, Ld01/i0;->l:Ld01/i0;

    .line 84
    .line 85
    filled-new-array/range {v0 .. v6}, [Ld01/i0;

    .line 86
    .line 87
    .line 88
    move-result-object v0

    .line 89
    sput-object v0, Ld01/i0;->m:[Ld01/i0;

    .line 90
    .line 91
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 92
    .line 93
    .line 94
    new-instance v0, Ld01/r;

    .line 95
    .line 96
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 97
    .line 98
    .line 99
    sput-object v0, Ld01/i0;->e:Ld01/r;

    .line 100
    .line 101
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;ILjava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput-object p3, p0, Ld01/i0;->d:Ljava/lang/String;

    .line 5
    .line 6
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Ld01/i0;
    .locals 1

    .line 1
    const-class v0, Ld01/i0;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ld01/i0;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Ld01/i0;
    .locals 1

    .line 1
    sget-object v0, Ld01/i0;->m:[Ld01/i0;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Ld01/i0;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public final toString()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Ld01/i0;->d:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method
