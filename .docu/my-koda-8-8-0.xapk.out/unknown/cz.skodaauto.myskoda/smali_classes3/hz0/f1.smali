.class public abstract Lhz0/f1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ljz0/u;

.field public static final b:Ljz0/u;

.field public static final c:Ljz0/u;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    new-instance v4, Lhz0/d1;

    .line 2
    .line 3
    invoke-direct {v4}, Lhz0/d1;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v1, Ljz0/r;

    .line 7
    .line 8
    sget-object v0, Lhz0/e1;->d:Lhz0/e1;

    .line 9
    .line 10
    invoke-interface {v0}, Lhy0/c;->getName()Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    invoke-direct {v1, v0, v2}, Ljz0/r;-><init>(Lhy0/l;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    new-instance v0, Ljz0/u;

    .line 18
    .line 19
    const/16 v3, 0x12

    .line 20
    .line 21
    const/16 v5, 0x8

    .line 22
    .line 23
    const/4 v2, 0x0

    .line 24
    invoke-direct/range {v0 .. v5}, Ljz0/u;-><init>(Ljz0/r;IILhz0/d1;I)V

    .line 25
    .line 26
    .line 27
    sput-object v0, Lhz0/f1;->a:Ljz0/u;

    .line 28
    .line 29
    new-instance v1, Ljz0/r;

    .line 30
    .line 31
    sget-object v0, Lhz0/a1;->d:Lhz0/a1;

    .line 32
    .line 33
    invoke-interface {v0}, Lhy0/c;->getName()Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object v2

    .line 37
    invoke-direct {v1, v0, v2}, Ljz0/r;-><init>(Lhy0/l;Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    new-instance v0, Ljz0/u;

    .line 41
    .line 42
    const/16 v3, 0x3b

    .line 43
    .line 44
    const/4 v2, 0x0

    .line 45
    invoke-direct/range {v0 .. v5}, Ljz0/u;-><init>(Ljz0/r;IILhz0/d1;I)V

    .line 46
    .line 47
    .line 48
    sput-object v0, Lhz0/f1;->b:Ljz0/u;

    .line 49
    .line 50
    new-instance v1, Ljz0/r;

    .line 51
    .line 52
    sget-object v0, Lhz0/b1;->d:Lhz0/b1;

    .line 53
    .line 54
    invoke-interface {v0}, Lhy0/c;->getName()Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object v2

    .line 58
    invoke-direct {v1, v0, v2}, Ljz0/r;-><init>(Lhy0/l;Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    new-instance v0, Ljz0/u;

    .line 62
    .line 63
    const/4 v2, 0x0

    .line 64
    invoke-direct/range {v0 .. v5}, Ljz0/u;-><init>(Ljz0/r;IILhz0/d1;I)V

    .line 65
    .line 66
    .line 67
    sput-object v0, Lhz0/f1;->c:Ljz0/u;

    .line 68
    .line 69
    return-void
.end method
