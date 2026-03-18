.class public final Llk0/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Llk0/c;

.field public final b:Lsf0/a;

.field public final c:Ljk0/c;


# direct methods
.method public constructor <init>(Llk0/c;Lsf0/a;Ljk0/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Llk0/l;->a:Llk0/c;

    .line 5
    .line 6
    iput-object p2, p0, Llk0/l;->b:Lsf0/a;

    .line 7
    .line 8
    iput-object p3, p0, Llk0/l;->c:Ljk0/c;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lmk0/c;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Llk0/l;->b(Lmk0/c;)Lam0/i;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lmk0/c;)Lam0/i;
    .locals 5

    .line 1
    const-string v0, "favouritePlaceToChange"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Llk0/l;->c:Ljk0/c;

    .line 7
    .line 8
    iget-object v1, v0, Ljk0/c;->a:Lxl0/f;

    .line 9
    .line 10
    new-instance v2, Ljk0/b;

    .line 11
    .line 12
    const/4 v3, 0x1

    .line 13
    const/4 v4, 0x0

    .line 14
    invoke-direct {v2, v0, p1, v4, v3}, Ljk0/b;-><init>(Ljk0/c;Lmk0/c;Lkotlin/coroutines/Continuation;I)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {v1, v2}, Lxl0/f;->c(Lay0/k;)Lyy0/m1;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    new-instance v0, Lk20/a;

    .line 22
    .line 23
    const/16 v1, 0xf

    .line 24
    .line 25
    invoke-direct {v0, p0, v4, v1}, Lk20/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 26
    .line 27
    .line 28
    invoke-static {v0, p1}, Lbb/j0;->f(Lay0/n;Lyy0/i;)Lne0/n;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    iget-object p0, p0, Llk0/l;->b:Lsf0/a;

    .line 33
    .line 34
    invoke-static {p1, p0, v4}, Llp/o1;->d(Lyy0/i;Lsf0/a;Ljava/lang/String;)Lam0/i;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    return-object p0
.end method
