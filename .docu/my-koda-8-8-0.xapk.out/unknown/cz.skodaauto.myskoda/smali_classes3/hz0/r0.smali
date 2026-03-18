.class public abstract Lhz0/r0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Llx0/q;

.field public static final b:Lhz0/i0;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lhz/a;

    .line 2
    .line 3
    const/4 v1, 0x6

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
    sput-object v0, Lhz0/r0;->a:Llx0/q;

    .line 12
    .line 13
    new-instance v0, Lhz0/i0;

    .line 14
    .line 15
    new-instance v1, Lhz0/h0;

    .line 16
    .line 17
    invoke-direct {v1}, Lhz0/h0;-><init>()V

    .line 18
    .line 19
    .line 20
    new-instance v2, Lhz0/j0;

    .line 21
    .line 22
    invoke-direct {v2}, Lhz0/j0;-><init>()V

    .line 23
    .line 24
    .line 25
    invoke-direct {v0, v1, v2}, Lhz0/i0;-><init>(Lhz0/h0;Lhz0/j0;)V

    .line 26
    .line 27
    .line 28
    sput-object v0, Lhz0/r0;->b:Lhz0/i0;

    .line 29
    .line 30
    return-void
.end method
