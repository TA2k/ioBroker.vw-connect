.class public final Lwr0/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lur0/b;

.field public final b:Lwr0/g;

.field public final c:Lsf0/a;


# direct methods
.method public constructor <init>(Lur0/b;Lwr0/g;Lsf0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lwr0/p;->a:Lur0/b;

    .line 5
    .line 6
    iput-object p2, p0, Lwr0/p;->b:Lwr0/g;

    .line 7
    .line 8
    iput-object p3, p0, Lwr0/p;->c:Lsf0/a;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a(Lyr0/c;)Lam0/i;
    .locals 6

    .line 1
    sget-object v0, Lyr0/b;->a:[I

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    aget v0, v0, v1

    .line 8
    .line 9
    const/4 v1, 0x1

    .line 10
    if-ne v0, v1, :cond_0

    .line 11
    .line 12
    sget-object v0, Lcq0/c;->d:Lcq0/c;

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    sget-object v0, Lcq0/c;->e:Lcq0/c;

    .line 16
    .line 17
    :goto_0
    invoke-virtual {v0}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    sget-object v1, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 22
    .line 23
    invoke-virtual {v0, v1}, Ljava/lang/String;->toUpperCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    const-string v1, "toUpperCase(...)"

    .line 28
    .line 29
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    iget-object v1, p0, Lwr0/p;->a:Lur0/b;

    .line 33
    .line 34
    iget-object v2, v1, Lur0/b;->a:Lxl0/f;

    .line 35
    .line 36
    new-instance v3, Lur0/a;

    .line 37
    .line 38
    const/4 v4, 0x1

    .line 39
    const/4 v5, 0x0

    .line 40
    invoke-direct {v3, v1, v0, v5, v4}, Lur0/a;-><init>(Lur0/b;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {v2, v3}, Lxl0/f;->c(Lay0/k;)Lyy0/m1;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    new-instance v1, Lwp0/c;

    .line 48
    .line 49
    const/4 v2, 0x1

    .line 50
    invoke-direct {v1, v2, p0, p1, v5}, Lwp0/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 51
    .line 52
    .line 53
    invoke-static {v1, v0}, Lbb/j0;->f(Lay0/n;Lyy0/i;)Lne0/n;

    .line 54
    .line 55
    .line 56
    move-result-object p1

    .line 57
    iget-object p0, p0, Lwr0/p;->c:Lsf0/a;

    .line 58
    .line 59
    invoke-static {p1, p0, v5}, Llp/o1;->d(Lyy0/i;Lsf0/a;Ljava/lang/String;)Lam0/i;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    return-object p0
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Lyr0/c;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Lwr0/p;->a(Lyr0/c;)Lam0/i;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
