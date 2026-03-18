.class public final Las0/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lme0/a;


# instance fields
.field public final a:Lti0/a;

.field public final b:Lal0/i;


# direct methods
.method public constructor <init>(Lti0/a;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Las0/g;->a:Lti0/a;

    .line 5
    .line 6
    new-instance p1, La7/o;

    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    const/4 v1, 0x7

    .line 10
    invoke-direct {p1, p0, v0, v1}, La7/o;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 11
    .line 12
    .line 13
    new-instance v0, Lyy0/m1;

    .line 14
    .line 15
    invoke-direct {v0, p1}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 16
    .line 17
    .line 18
    new-instance p1, Lal0/i;

    .line 19
    .line 20
    const/4 v1, 0x2

    .line 21
    invoke-direct {p1, v0, v1}, Lal0/i;-><init>(Lyy0/m1;I)V

    .line 22
    .line 23
    .line 24
    iput-object p1, p0, Las0/g;->b:Lal0/i;

    .line 25
    .line 26
    return-void
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 4

    .line 1
    sget-object v0, Lge0/b;->a:Lcz0/e;

    .line 2
    .line 3
    new-instance v1, La50/a;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/4 v3, 0x5

    .line 7
    invoke-direct {v1, p0, v2, v3}, La50/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 8
    .line 9
    .line 10
    invoke-static {v0, v1, p1}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 15
    .line 16
    if-ne p0, p1, :cond_0

    .line 17
    .line 18
    return-object p0

    .line 19
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 20
    .line 21
    return-object p0
.end method

.method public final b(Lds0/e;Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    sget-object v0, Lge0/b;->a:Lcz0/e;

    .line 2
    .line 3
    new-instance v1, La50/c;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/4 v3, 0x5

    .line 7
    invoke-direct {v1, v3, p0, p1, v2}, La50/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 8
    .line 9
    .line 10
    invoke-static {v0, v1, p2}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 15
    .line 16
    if-ne p0, p1, :cond_0

    .line 17
    .line 18
    return-object p0

    .line 19
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 20
    .line 21
    return-object p0
.end method
