.class public abstract Lhz0/u0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Llx0/q;

.field public static final b:Lhz0/j0;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lhz/a;

    .line 2
    .line 3
    const/4 v1, 0x7

    .line 4
    invoke-direct {v0, v1}, Lhz/a;-><init>(I)V

    .line 5
    .line 6
    .line 7
    invoke-static {v0}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sput-object v0, Lhz0/u0;->a:Llx0/q;

    .line 12
    .line 13
    new-instance v0, Lhz0/j0;

    .line 14
    .line 15
    invoke-direct {v0}, Lhz0/j0;-><init>()V

    .line 16
    .line 17
    .line 18
    sput-object v0, Lhz0/u0;->b:Lhz0/j0;

    .line 19
    .line 20
    return-void
.end method
