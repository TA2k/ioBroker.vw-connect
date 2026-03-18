.class public final Lhc0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ldm0/l;


# instance fields
.field public final a:Lgc0/c;


# direct methods
.method public constructor <init>(Lgc0/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lhc0/a;->a:Lgc0/c;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lcm0/b;Ld01/k0;)Ld01/k0;
    .locals 2

    .line 1
    const-string v0, "environment"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p1, "request"

    .line 7
    .line 8
    invoke-static {p2, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance p1, Lh40/h;

    .line 12
    .line 13
    const/16 v0, 0xb

    .line 14
    .line 15
    const/4 v1, 0x0

    .line 16
    invoke-direct {p1, p0, v1, v0}, Lh40/h;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 17
    .line 18
    .line 19
    sget-object p0, Lpx0/h;->d:Lpx0/h;

    .line 20
    .line 21
    invoke-static {p0, p1}, Lvy0/e0;->K(Lpx0/g;Lay0/n;)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    check-cast p0, Ljava/lang/String;

    .line 26
    .line 27
    invoke-virtual {p2}, Ld01/k0;->b()Ld01/j0;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    const-string p2, "X-App-Check-Token"

    .line 32
    .line 33
    invoke-virtual {p1, p2, p0}, Ld01/j0;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    new-instance p0, Ld01/k0;

    .line 37
    .line 38
    invoke-direct {p0, p1}, Ld01/k0;-><init>(Ld01/j0;)V

    .line 39
    .line 40
    .line 41
    return-object p0
.end method
