.class public final Lo20/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lm20/j;

.field public final b:Lm20/d;


# direct methods
.method public constructor <init>(Lm20/j;Lm20/d;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lo20/a;->a:Lm20/j;

    .line 5
    .line 6
    iput-object p2, p0, Lo20/a;->b:Lm20/d;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lss0/j0;

    .line 2
    .line 3
    iget-object p1, p1, Lss0/j0;->d:Ljava/lang/String;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Lo20/a;->b(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public final b(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object p2, p0, Lo20/a;->b:Lm20/d;

    .line 2
    .line 3
    const-string v0, "$v$c$cz-skodaauto-myskoda-library-vehicle-model-Vin$-vin$0"

    .line 4
    .line 5
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v0, p2, Lm20/d;->a:Lxl0/f;

    .line 9
    .line 10
    new-instance v1, Llo0/b;

    .line 11
    .line 12
    const/4 v2, 0x2

    .line 13
    const/4 v3, 0x0

    .line 14
    invoke-direct {v1, v2, p2, p1, v3}, Llo0/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 15
    .line 16
    .line 17
    sget-object p2, Lm20/c;->d:Lm20/c;

    .line 18
    .line 19
    invoke-virtual {v0, v1, p2, v3}, Lxl0/f;->e(Lay0/k;Lay0/k;Lay0/k;)Lyy0/m1;

    .line 20
    .line 21
    .line 22
    move-result-object p2

    .line 23
    new-instance v0, Lny/f0;

    .line 24
    .line 25
    const/4 v1, 0x5

    .line 26
    invoke-direct {v0, v1, p0, p1, v3}, Lny/f0;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 27
    .line 28
    .line 29
    new-instance p0, Lne0/n;

    .line 30
    .line 31
    const/4 p1, 0x5

    .line 32
    invoke-direct {p0, p2, v0, p1}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 33
    .line 34
    .line 35
    return-object p0
.end method
