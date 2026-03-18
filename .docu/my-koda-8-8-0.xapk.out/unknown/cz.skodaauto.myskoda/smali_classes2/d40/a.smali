.class public final Ld40/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lf40/y0;
.implements Lme0/a;


# instance fields
.field public final a:Lwe0/a;

.field public final b:Lwe0/a;

.field public c:Lg40/v0;

.field public final d:Lez0/c;

.field public final e:Lyy0/c2;

.field public final f:Lyy0/l1;

.field public final g:Lyy0/c2;

.field public final h:Lyy0/l1;


# direct methods
.method public constructor <init>(Lwe0/a;Lwe0/a;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ld40/a;->a:Lwe0/a;

    .line 5
    .line 6
    iput-object p2, p0, Ld40/a;->b:Lwe0/a;

    .line 7
    .line 8
    invoke-static {}, Lez0/d;->a()Lez0/c;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    iput-object p1, p0, Ld40/a;->d:Lez0/c;

    .line 13
    .line 14
    sget-object p1, Lne0/d;->a:Lne0/d;

    .line 15
    .line 16
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 17
    .line 18
    .line 19
    move-result-object p2

    .line 20
    iput-object p2, p0, Ld40/a;->e:Lyy0/c2;

    .line 21
    .line 22
    new-instance v0, Lyy0/l1;

    .line 23
    .line 24
    invoke-direct {v0, p2}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 25
    .line 26
    .line 27
    iput-object v0, p0, Ld40/a;->f:Lyy0/l1;

    .line 28
    .line 29
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 30
    .line 31
    .line 32
    move-result-object p1

    .line 33
    iput-object p1, p0, Ld40/a;->g:Lyy0/c2;

    .line 34
    .line 35
    new-instance p2, Lyy0/l1;

    .line 36
    .line 37
    invoke-direct {p2, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 38
    .line 39
    .line 40
    iput-object p2, p0, Ld40/a;->h:Lyy0/l1;

    .line 41
    .line 42
    return-void
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 3

    .line 1
    :cond_0
    iget-object p1, p0, Ld40/a;->e:Lyy0/c2;

    .line 2
    .line 3
    invoke-virtual {p1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    move-object v1, v0

    .line 8
    check-cast v1, Lne0/s;

    .line 9
    .line 10
    sget-object v1, Lne0/d;->a:Lne0/d;

    .line 11
    .line 12
    invoke-virtual {p1, v0, v1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    move-result p1

    .line 16
    if-eqz p1, :cond_0

    .line 17
    .line 18
    :cond_1
    iget-object p1, p0, Ld40/a;->g:Lyy0/c2;

    .line 19
    .line 20
    invoke-virtual {p1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    move-object v2, v0

    .line 25
    check-cast v2, Lne0/s;

    .line 26
    .line 27
    invoke-virtual {p1, v0, v1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result p1

    .line 31
    if-eqz p1, :cond_1

    .line 32
    .line 33
    iget-object p1, p0, Ld40/a;->a:Lwe0/a;

    .line 34
    .line 35
    check-cast p1, Lwe0/c;

    .line 36
    .line 37
    invoke-virtual {p1}, Lwe0/c;->a()V

    .line 38
    .line 39
    .line 40
    iget-object p0, p0, Ld40/a;->b:Lwe0/a;

    .line 41
    .line 42
    check-cast p0, Lwe0/c;

    .line 43
    .line 44
    invoke-virtual {p0}, Lwe0/c;->a()V

    .line 45
    .line 46
    .line 47
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 48
    .line 49
    return-object p0
.end method
