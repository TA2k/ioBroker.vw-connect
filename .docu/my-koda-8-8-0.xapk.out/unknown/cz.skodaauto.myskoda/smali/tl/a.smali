.class public final enum Ltl/a;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum f:Ltl/a;

.field public static final enum g:Ltl/a;

.field public static final synthetic h:[Ltl/a;


# instance fields
.field public final d:Z

.field public final e:Z


# direct methods
.method static constructor <clinit>()V
    .locals 7

    .line 1
    new-instance v0, Ltl/a;

    .line 2
    .line 3
    const-string v1, "ENABLED"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/4 v3, 0x1

    .line 7
    invoke-direct {v0, v1, v2, v3, v3}, Ltl/a;-><init>(Ljava/lang/String;IZZ)V

    .line 8
    .line 9
    .line 10
    sput-object v0, Ltl/a;->f:Ltl/a;

    .line 11
    .line 12
    new-instance v1, Ltl/a;

    .line 13
    .line 14
    const-string v4, "READ_ONLY"

    .line 15
    .line 16
    invoke-direct {v1, v4, v3, v3, v2}, Ltl/a;-><init>(Ljava/lang/String;IZZ)V

    .line 17
    .line 18
    .line 19
    new-instance v4, Ltl/a;

    .line 20
    .line 21
    const-string v5, "WRITE_ONLY"

    .line 22
    .line 23
    const/4 v6, 0x2

    .line 24
    invoke-direct {v4, v5, v6, v2, v3}, Ltl/a;-><init>(Ljava/lang/String;IZZ)V

    .line 25
    .line 26
    .line 27
    new-instance v3, Ltl/a;

    .line 28
    .line 29
    const-string v5, "DISABLED"

    .line 30
    .line 31
    const/4 v6, 0x3

    .line 32
    invoke-direct {v3, v5, v6, v2, v2}, Ltl/a;-><init>(Ljava/lang/String;IZZ)V

    .line 33
    .line 34
    .line 35
    sput-object v3, Ltl/a;->g:Ltl/a;

    .line 36
    .line 37
    filled-new-array {v0, v1, v4, v3}, [Ltl/a;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    sput-object v0, Ltl/a;->h:[Ltl/a;

    .line 42
    .line 43
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 44
    .line 45
    .line 46
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;IZZ)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput-boolean p3, p0, Ltl/a;->d:Z

    .line 5
    .line 6
    iput-boolean p4, p0, Ltl/a;->e:Z

    .line 7
    .line 8
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Ltl/a;
    .locals 1

    .line 1
    const-class v0, Ltl/a;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ltl/a;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Ltl/a;
    .locals 1

    .line 1
    sget-object v0, Ltl/a;->h:[Ltl/a;

    .line 2
    .line 3
    invoke-virtual {v0}, [Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Ltl/a;

    .line 8
    .line 9
    return-object v0
.end method
