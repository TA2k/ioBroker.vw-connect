.class public final Lk4/s;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final c:Lk4/r;


# instance fields
.field public final a:Lil/g;

.field public final b:Lpw0/a;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lk4/r;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    sget-object v2, Lvy0/y;->d:Lvy0/y;

    .line 5
    .line 6
    invoke-direct {v0, v2, v1}, Lk4/r;-><init>(Lpx0/f;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lk4/s;->c:Lk4/r;

    .line 10
    .line 11
    return-void
.end method

.method public constructor <init>(Lil/g;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lk4/s;->a:Lil/g;

    .line 5
    .line 6
    sget-object p1, Lk4/s;->c:Lk4/r;

    .line 7
    .line 8
    sget-object v0, Lo4/g;->a:Lwy0/c;

    .line 9
    .line 10
    invoke-interface {p1, v0}, Lpx0/g;->plus(Lpx0/g;)Lpx0/g;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    sget-object v0, Lpx0/h;->d:Lpx0/h;

    .line 15
    .line 16
    invoke-interface {p1, v0}, Lpx0/g;->plus(Lpx0/g;)Lpx0/g;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    new-instance v0, Lvy0/z1;

    .line 21
    .line 22
    const/4 v1, 0x0

    .line 23
    invoke-direct {v0, v1}, Lvy0/k1;-><init>(Lvy0/i1;)V

    .line 24
    .line 25
    .line 26
    invoke-interface {p1, v0}, Lpx0/g;->plus(Lpx0/g;)Lpx0/g;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    invoke-static {p1}, Lvy0/e0;->c(Lpx0/g;)Lpw0/a;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    iput-object p1, p0, Lk4/s;->b:Lpw0/a;

    .line 35
    .line 36
    return-void
.end method
