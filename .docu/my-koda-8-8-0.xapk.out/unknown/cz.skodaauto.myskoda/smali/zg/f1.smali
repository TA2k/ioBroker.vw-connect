.class public final enum Lzg/f1;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lzg/f1;",
        ">;"
    }
.end annotation

.annotation runtime Lqz0/g;
.end annotation


# static fields
.field public static final Companion:Lzg/e1;

.field public static final d:Ljava/lang/Object;

.field public static final enum e:Lzg/f1;

.field public static final synthetic f:[Lzg/f1;

.field public static final synthetic g:Lsx0/b;


# direct methods
.method static constructor <clinit>()V
    .locals 10

    .line 1
    new-instance v0, Lzg/f1;

    .line 2
    .line 3
    const-string v1, "South"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lzg/f1;->e:Lzg/f1;

    .line 10
    .line 11
    new-instance v1, Lzg/f1;

    .line 12
    .line 13
    const-string v2, "SouthWest"

    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    new-instance v2, Lzg/f1;

    .line 20
    .line 21
    const-string v3, "SouthEast"

    .line 22
    .line 23
    const/4 v4, 0x2

    .line 24
    invoke-direct {v2, v3, v4}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 25
    .line 26
    .line 27
    new-instance v3, Lzg/f1;

    .line 28
    .line 29
    const-string v4, "West"

    .line 30
    .line 31
    const/4 v5, 0x3

    .line 32
    invoke-direct {v3, v4, v5}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 33
    .line 34
    .line 35
    new-instance v4, Lzg/f1;

    .line 36
    .line 37
    const-string v5, "East"

    .line 38
    .line 39
    const/4 v6, 0x4

    .line 40
    invoke-direct {v4, v5, v6}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 41
    .line 42
    .line 43
    new-instance v5, Lzg/f1;

    .line 44
    .line 45
    const-string v6, "North"

    .line 46
    .line 47
    const/4 v7, 0x5

    .line 48
    invoke-direct {v5, v6, v7}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 49
    .line 50
    .line 51
    new-instance v6, Lzg/f1;

    .line 52
    .line 53
    const-string v7, "NorthWest"

    .line 54
    .line 55
    const/4 v8, 0x6

    .line 56
    invoke-direct {v6, v7, v8}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 57
    .line 58
    .line 59
    new-instance v7, Lzg/f1;

    .line 60
    .line 61
    const-string v8, "NorthEast"

    .line 62
    .line 63
    const/4 v9, 0x7

    .line 64
    invoke-direct {v7, v8, v9}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 65
    .line 66
    .line 67
    filled-new-array/range {v0 .. v7}, [Lzg/f1;

    .line 68
    .line 69
    .line 70
    move-result-object v0

    .line 71
    sput-object v0, Lzg/f1;->f:[Lzg/f1;

    .line 72
    .line 73
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    sput-object v0, Lzg/f1;->g:Lsx0/b;

    .line 78
    .line 79
    new-instance v0, Lzg/e1;

    .line 80
    .line 81
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 82
    .line 83
    .line 84
    sput-object v0, Lzg/f1;->Companion:Lzg/e1;

    .line 85
    .line 86
    sget-object v0, Llx0/j;->e:Llx0/j;

    .line 87
    .line 88
    new-instance v1, Lz81/g;

    .line 89
    .line 90
    const/16 v2, 0x14

    .line 91
    .line 92
    invoke-direct {v1, v2}, Lz81/g;-><init>(I)V

    .line 93
    .line 94
    .line 95
    invoke-static {v0, v1}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 96
    .line 97
    .line 98
    move-result-object v0

    .line 99
    sput-object v0, Lzg/f1;->d:Ljava/lang/Object;

    .line 100
    .line 101
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lzg/f1;
    .locals 1

    .line 1
    const-class v0, Lzg/f1;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lzg/f1;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lzg/f1;
    .locals 1

    .line 1
    sget-object v0, Lzg/f1;->f:[Lzg/f1;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lzg/f1;

    .line 8
    .line 9
    return-object v0
.end method
