.class public abstract Lhz0/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lhz0/s;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    sget-object v0, Lhz0/p;->b:La61/a;

    .line 2
    .line 3
    new-instance v1, Lh70/f;

    .line 4
    .line 5
    const/16 v2, 0xa

    .line 6
    .line 7
    invoke-direct {v1, v2}, Lh70/f;-><init>(I)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    new-instance v0, Lhz0/r;

    .line 14
    .line 15
    new-instance v2, Lbn/c;

    .line 16
    .line 17
    const/4 v3, 0x3

    .line 18
    invoke-direct {v2, v3}, Lbn/c;-><init>(I)V

    .line 19
    .line 20
    .line 21
    invoke-direct {v0, v2}, Lhz0/r;-><init>(Lbn/c;)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {v1, v0}, Lh70/f;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    new-instance v1, Lhz0/s;

    .line 28
    .line 29
    invoke-interface {v0}, Lhz0/b;->build()Ljz0/d;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    const/4 v2, 0x0

    .line 34
    invoke-direct {v1, v0, v2}, Lhz0/s;-><init>(Ljz0/d;I)V

    .line 35
    .line 36
    .line 37
    sput-object v1, Lhz0/n;->a:Lhz0/s;

    .line 38
    .line 39
    new-instance v0, Lh70/f;

    .line 40
    .line 41
    const/16 v1, 0xf

    .line 42
    .line 43
    invoke-direct {v0, v1}, Lh70/f;-><init>(I)V

    .line 44
    .line 45
    .line 46
    new-instance v1, Lhz0/r;

    .line 47
    .line 48
    new-instance v2, Lbn/c;

    .line 49
    .line 50
    invoke-direct {v2, v3}, Lbn/c;-><init>(I)V

    .line 51
    .line 52
    .line 53
    invoke-direct {v1, v2}, Lhz0/r;-><init>(Lbn/c;)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {v0, v1}, Lh70/f;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    invoke-interface {v1}, Lhz0/b;->build()Ljz0/d;

    .line 60
    .line 61
    .line 62
    return-void
.end method
