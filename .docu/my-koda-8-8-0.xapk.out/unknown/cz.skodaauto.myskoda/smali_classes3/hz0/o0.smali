.class public abstract Lhz0/o0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Llx0/q;

.field public static final b:Llx0/q;

.field public static final c:Lhz0/h0;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lhz/a;

    .line 2
    .line 3
    const/4 v1, 0x4

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
    sput-object v0, Lhz0/o0;->a:Llx0/q;

    .line 12
    .line 13
    new-instance v0, Lhz/a;

    .line 14
    .line 15
    const/4 v1, 0x5

    .line 16
    invoke-direct {v0, v1}, Lhz/a;-><init>(I)V

    .line 17
    .line 18
    .line 19
    invoke-static {v0}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    sput-object v0, Lhz0/o0;->b:Llx0/q;

    .line 24
    .line 25
    new-instance v0, Lhz0/h0;

    .line 26
    .line 27
    invoke-direct {v0}, Lhz0/h0;-><init>()V

    .line 28
    .line 29
    .line 30
    sput-object v0, Lhz0/o0;->c:Lhz0/h0;

    .line 31
    .line 32
    return-void
.end method
