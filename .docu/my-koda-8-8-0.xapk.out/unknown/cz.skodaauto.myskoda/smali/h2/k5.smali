.class public abstract Lh2/k5;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lt3/o;

.field public static final b:Lt3/r1;

.field public static final c:Ll2/u2;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lt3/o;

    .line 2
    .line 3
    sget-object v1, Lh2/j5;->d:Lh2/j5;

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lt3/a;-><init>(Lay0/n;)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lh2/k5;->a:Lt3/o;

    .line 9
    .line 10
    new-instance v0, Lt3/r1;

    .line 11
    .line 12
    sget-object v1, Lh2/i5;->d:Lh2/i5;

    .line 13
    .line 14
    invoke-direct {v0, v1}, Lt3/a;-><init>(Lay0/n;)V

    .line 15
    .line 16
    .line 17
    sput-object v0, Lh2/k5;->b:Lt3/r1;

    .line 18
    .line 19
    new-instance v0, Lgz0/e0;

    .line 20
    .line 21
    const/16 v1, 0xc

    .line 22
    .line 23
    invoke-direct {v0, v1}, Lgz0/e0;-><init>(I)V

    .line 24
    .line 25
    .line 26
    invoke-static {v0}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 27
    .line 28
    .line 29
    new-instance v0, Lgz0/e0;

    .line 30
    .line 31
    const/16 v1, 0xd

    .line 32
    .line 33
    invoke-direct {v0, v1}, Lgz0/e0;-><init>(I)V

    .line 34
    .line 35
    .line 36
    new-instance v1, Ll2/u2;

    .line 37
    .line 38
    invoke-direct {v1, v0}, Ll2/s1;-><init>(Lay0/a;)V

    .line 39
    .line 40
    .line 41
    sput-object v1, Lh2/k5;->c:Ll2/u2;

    .line 42
    .line 43
    return-void
.end method
