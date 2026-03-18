.class public final enum Lwz0/f0;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum f:Lwz0/f0;

.field public static final enum g:Lwz0/f0;

.field public static final enum h:Lwz0/f0;

.field public static final enum i:Lwz0/f0;

.field public static final synthetic j:[Lwz0/f0;

.field public static final synthetic k:Lsx0/b;


# instance fields
.field public final d:C

.field public final e:C


# direct methods
.method static constructor <clinit>()V
    .locals 9

    .line 1
    new-instance v0, Lwz0/f0;

    .line 2
    .line 3
    const-string v1, "OBJ"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/16 v3, 0x7b

    .line 7
    .line 8
    const/16 v4, 0x7d

    .line 9
    .line 10
    invoke-direct {v0, v1, v2, v3, v4}, Lwz0/f0;-><init>(Ljava/lang/String;ICC)V

    .line 11
    .line 12
    .line 13
    sput-object v0, Lwz0/f0;->f:Lwz0/f0;

    .line 14
    .line 15
    new-instance v1, Lwz0/f0;

    .line 16
    .line 17
    const-string v2, "LIST"

    .line 18
    .line 19
    const/4 v5, 0x1

    .line 20
    const/16 v6, 0x5b

    .line 21
    .line 22
    const/16 v7, 0x5d

    .line 23
    .line 24
    invoke-direct {v1, v2, v5, v6, v7}, Lwz0/f0;-><init>(Ljava/lang/String;ICC)V

    .line 25
    .line 26
    .line 27
    sput-object v1, Lwz0/f0;->g:Lwz0/f0;

    .line 28
    .line 29
    new-instance v2, Lwz0/f0;

    .line 30
    .line 31
    const-string v5, "MAP"

    .line 32
    .line 33
    const/4 v8, 0x2

    .line 34
    invoke-direct {v2, v5, v8, v3, v4}, Lwz0/f0;-><init>(Ljava/lang/String;ICC)V

    .line 35
    .line 36
    .line 37
    sput-object v2, Lwz0/f0;->h:Lwz0/f0;

    .line 38
    .line 39
    new-instance v3, Lwz0/f0;

    .line 40
    .line 41
    const-string v4, "POLY_OBJ"

    .line 42
    .line 43
    const/4 v5, 0x3

    .line 44
    invoke-direct {v3, v4, v5, v6, v7}, Lwz0/f0;-><init>(Ljava/lang/String;ICC)V

    .line 45
    .line 46
    .line 47
    sput-object v3, Lwz0/f0;->i:Lwz0/f0;

    .line 48
    .line 49
    filled-new-array {v0, v1, v2, v3}, [Lwz0/f0;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    sput-object v0, Lwz0/f0;->j:[Lwz0/f0;

    .line 54
    .line 55
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 56
    .line 57
    .line 58
    move-result-object v0

    .line 59
    sput-object v0, Lwz0/f0;->k:Lsx0/b;

    .line 60
    .line 61
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;ICC)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput-char p3, p0, Lwz0/f0;->d:C

    .line 5
    .line 6
    iput-char p4, p0, Lwz0/f0;->e:C

    .line 7
    .line 8
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lwz0/f0;
    .locals 1

    .line 1
    const-class v0, Lwz0/f0;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lwz0/f0;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lwz0/f0;
    .locals 1

    .line 1
    sget-object v0, Lwz0/f0;->j:[Lwz0/f0;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lwz0/f0;

    .line 8
    .line 9
    return-object v0
.end method
