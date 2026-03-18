.class public abstract Lhz0/u;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lhz0/q;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    sget-object v0, Lhz0/t;->d:Lhz0/t;

    .line 2
    .line 3
    invoke-interface {v0}, Lhy0/c;->getName()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const-string v1, "name"

    .line 8
    .line 9
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    new-instance v0, Lhz0/q;

    .line 13
    .line 14
    new-instance v1, Lhz0/h0;

    .line 15
    .line 16
    invoke-direct {v1}, Lhz0/h0;-><init>()V

    .line 17
    .line 18
    .line 19
    new-instance v2, Lhz0/j0;

    .line 20
    .line 21
    invoke-direct {v2}, Lhz0/j0;-><init>()V

    .line 22
    .line 23
    .line 24
    new-instance v3, Lhz0/k0;

    .line 25
    .line 26
    const/4 v4, 0x0

    .line 27
    invoke-direct {v3, v4, v4, v4, v4}, Lhz0/k0;-><init>(Ljava/lang/Boolean;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;)V

    .line 28
    .line 29
    .line 30
    invoke-direct {v0, v1, v2, v3, v4}, Lhz0/q;-><init>(Lhz0/h0;Lhz0/j0;Lhz0/k0;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    sput-object v0, Lhz0/u;->a:Lhz0/q;

    .line 34
    .line 35
    return-void
.end method
