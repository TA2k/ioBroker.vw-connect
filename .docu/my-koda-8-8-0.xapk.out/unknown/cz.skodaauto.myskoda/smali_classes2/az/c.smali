.class public final enum Laz/c;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum f:Laz/c;

.field public static final enum g:Laz/c;

.field public static final enum h:Laz/c;

.field public static final enum i:Laz/c;

.field public static final enum j:Laz/c;

.field public static final enum k:Laz/c;

.field public static final enum l:Laz/c;

.field public static final enum m:Laz/c;

.field public static final synthetic n:[Laz/c;

.field public static final synthetic o:Lsx0/b;


# instance fields
.field public final d:Ljava/util/List;

.field public final e:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 12

    .line 1
    new-instance v0, Laz/c;

    .line 2
    .line 3
    sget-object v1, Laz/a;->n:Lsx0/b;

    .line 4
    .line 5
    const-string v2, "food"

    .line 6
    .line 7
    const-string v3, "Food"

    .line 8
    .line 9
    const/4 v4, 0x0

    .line 10
    invoke-direct {v0, v3, v4, v1, v2}, Laz/c;-><init>(Ljava/lang/String;ILsx0/b;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    sput-object v0, Laz/c;->f:Laz/c;

    .line 14
    .line 15
    new-instance v1, Laz/c;

    .line 16
    .line 17
    const-string v2, "Outdoors"

    .line 18
    .line 19
    const/4 v3, 0x1

    .line 20
    const/4 v4, 0x0

    .line 21
    const-string v5, "outdoor"

    .line 22
    .line 23
    invoke-direct {v1, v2, v3, v4, v5}, Laz/c;-><init>(Ljava/lang/String;ILsx0/b;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    sput-object v1, Laz/c;->g:Laz/c;

    .line 27
    .line 28
    new-instance v2, Laz/c;

    .line 29
    .line 30
    const/4 v3, 0x2

    .line 31
    const-string v5, "sport"

    .line 32
    .line 33
    const-string v6, "Sport"

    .line 34
    .line 35
    invoke-direct {v2, v6, v3, v4, v5}, Laz/c;-><init>(Ljava/lang/String;ILsx0/b;Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    sput-object v2, Laz/c;->h:Laz/c;

    .line 39
    .line 40
    new-instance v3, Laz/c;

    .line 41
    .line 42
    const/4 v5, 0x3

    .line 43
    const-string v6, "history"

    .line 44
    .line 45
    const-string v7, "History"

    .line 46
    .line 47
    invoke-direct {v3, v7, v5, v4, v6}, Laz/c;-><init>(Ljava/lang/String;ILsx0/b;Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    sput-object v3, Laz/c;->i:Laz/c;

    .line 51
    .line 52
    move-object v5, v4

    .line 53
    new-instance v4, Laz/c;

    .line 54
    .line 55
    const/4 v6, 0x4

    .line 56
    const-string v7, "culture"

    .line 57
    .line 58
    const-string v8, "Culture"

    .line 59
    .line 60
    invoke-direct {v4, v8, v6, v5, v7}, Laz/c;-><init>(Ljava/lang/String;ILsx0/b;Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    sput-object v4, Laz/c;->j:Laz/c;

    .line 64
    .line 65
    move-object v6, v5

    .line 66
    new-instance v5, Laz/c;

    .line 67
    .line 68
    const/4 v7, 0x5

    .line 69
    const-string v8, "entertainment"

    .line 70
    .line 71
    const-string v9, "Entertainment"

    .line 72
    .line 73
    invoke-direct {v5, v9, v7, v6, v8}, Laz/c;-><init>(Ljava/lang/String;ILsx0/b;Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    sput-object v5, Laz/c;->k:Laz/c;

    .line 77
    .line 78
    move-object v7, v6

    .line 79
    new-instance v6, Laz/c;

    .line 80
    .line 81
    const/4 v8, 0x6

    .line 82
    const-string v9, "shopping"

    .line 83
    .line 84
    const-string v10, "Shopping"

    .line 85
    .line 86
    invoke-direct {v6, v10, v8, v7, v9}, Laz/c;-><init>(Ljava/lang/String;ILsx0/b;Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    sput-object v6, Laz/c;->l:Laz/c;

    .line 90
    .line 91
    move-object v8, v7

    .line 92
    new-instance v7, Laz/c;

    .line 93
    .line 94
    const/4 v9, 0x7

    .line 95
    const-string v10, "wellness"

    .line 96
    .line 97
    const-string v11, "Wellness"

    .line 98
    .line 99
    invoke-direct {v7, v11, v9, v8, v10}, Laz/c;-><init>(Ljava/lang/String;ILsx0/b;Ljava/lang/String;)V

    .line 100
    .line 101
    .line 102
    sput-object v7, Laz/c;->m:Laz/c;

    .line 103
    .line 104
    filled-new-array/range {v0 .. v7}, [Laz/c;

    .line 105
    .line 106
    .line 107
    move-result-object v0

    .line 108
    sput-object v0, Laz/c;->n:[Laz/c;

    .line 109
    .line 110
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 111
    .line 112
    .line 113
    move-result-object v0

    .line 114
    sput-object v0, Laz/c;->o:Lsx0/b;

    .line 115
    .line 116
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;ILsx0/b;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput-object p3, p0, Laz/c;->d:Ljava/util/List;

    .line 5
    .line 6
    iput-object p4, p0, Laz/c;->e:Ljava/lang/String;

    .line 7
    .line 8
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Laz/c;
    .locals 1

    .line 1
    const-class v0, Laz/c;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Laz/c;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Laz/c;
    .locals 1

    .line 1
    sget-object v0, Laz/c;->n:[Laz/c;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Laz/c;

    .line 8
    .line 9
    return-object v0
.end method
