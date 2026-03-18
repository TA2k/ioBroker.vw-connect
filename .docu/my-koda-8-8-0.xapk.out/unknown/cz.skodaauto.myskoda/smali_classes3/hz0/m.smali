.class public abstract Lhz0/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ljz0/u;

.field public static final b:Ljz0/u;


# direct methods
.method static constructor <clinit>()V
    .locals 7

    .line 1
    new-instance v0, Ljz0/u;

    .line 2
    .line 3
    new-instance v1, Ljz0/r;

    .line 4
    .line 5
    sget-object v2, Lhz0/j;->d:Lhz0/j;

    .line 6
    .line 7
    invoke-interface {v2}, Lhy0/c;->getName()Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v3

    .line 11
    invoke-direct {v1, v2, v3}, Ljz0/r;-><init>(Lhy0/l;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    const/4 v4, 0x0

    .line 15
    const/16 v5, 0x38

    .line 16
    .line 17
    const/4 v2, 0x1

    .line 18
    const/16 v3, 0x1f

    .line 19
    .line 20
    invoke-direct/range {v0 .. v5}, Ljz0/u;-><init>(Ljz0/r;IILhz0/d1;I)V

    .line 21
    .line 22
    .line 23
    sput-object v0, Lhz0/m;->a:Ljz0/u;

    .line 24
    .line 25
    new-instance v1, Ljz0/u;

    .line 26
    .line 27
    new-instance v2, Ljz0/r;

    .line 28
    .line 29
    sget-object v0, Lhz0/l;->d:Lhz0/l;

    .line 30
    .line 31
    invoke-interface {v0}, Lhy0/c;->getName()Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object v3

    .line 35
    invoke-direct {v2, v0, v3}, Ljz0/r;-><init>(Lhy0/l;Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    const/4 v5, 0x0

    .line 39
    const/16 v6, 0x38

    .line 40
    .line 41
    const/4 v3, 0x1

    .line 42
    const/4 v4, 0x7

    .line 43
    invoke-direct/range {v1 .. v6}, Ljz0/u;-><init>(Ljz0/r;IILhz0/d1;I)V

    .line 44
    .line 45
    .line 46
    sput-object v1, Lhz0/m;->b:Ljz0/u;

    .line 47
    .line 48
    sget-object v0, Lhz0/k;->d:Lhz0/k;

    .line 49
    .line 50
    invoke-interface {v0}, Lhy0/c;->getName()Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    const-string v1, "name"

    .line 55
    .line 56
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    return-void
.end method
