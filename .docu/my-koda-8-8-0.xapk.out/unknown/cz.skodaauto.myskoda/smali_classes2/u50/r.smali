.class public final Lu50/r;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lrs0/g;

.field public final i:Ls50/o;

.field public final j:Ls50/q;

.field public final k:Ltr0/b;

.field public final l:Ls50/b0;

.field public final m:Ls50/b;

.field public final n:Lij0/a;


# direct methods
.method public constructor <init>(Lrs0/g;Ls50/o;Ls50/q;Ltr0/b;Ls50/b0;Ls50/b;Lij0/a;)V
    .locals 1

    .line 1
    new-instance v0, Lu50/p;

    .line 2
    .line 3
    invoke-direct {v0}, Lu50/p;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lu50/r;->h:Lrs0/g;

    .line 10
    .line 11
    iput-object p2, p0, Lu50/r;->i:Ls50/o;

    .line 12
    .line 13
    iput-object p3, p0, Lu50/r;->j:Ls50/q;

    .line 14
    .line 15
    iput-object p4, p0, Lu50/r;->k:Ltr0/b;

    .line 16
    .line 17
    iput-object p5, p0, Lu50/r;->l:Ls50/b0;

    .line 18
    .line 19
    iput-object p6, p0, Lu50/r;->m:Ls50/b;

    .line 20
    .line 21
    iput-object p7, p0, Lu50/r;->n:Lij0/a;

    .line 22
    .line 23
    new-instance p1, Lu50/o;

    .line 24
    .line 25
    const/4 p2, 0x0

    .line 26
    const/4 p3, 0x0

    .line 27
    invoke-direct {p1, p0, p3, p2}, Lu50/o;-><init>(Lu50/r;Lkotlin/coroutines/Continuation;I)V

    .line 28
    .line 29
    .line 30
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 31
    .line 32
    .line 33
    return-void
.end method

.method public static final h(Lu50/r;)Lql0/g;
    .locals 6

    .line 1
    iget-object v0, p0, Lu50/r;->n:Lij0/a;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    new-array v2, v1, [Ljava/lang/Object;

    .line 5
    .line 6
    move-object v3, v0

    .line 7
    check-cast v3, Ljj0/f;

    .line 8
    .line 9
    const v4, 0x7f1202be

    .line 10
    .line 11
    .line 12
    invoke-virtual {v3, v4, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object v2

    .line 16
    iget-object p0, p0, Lu50/r;->n:Lij0/a;

    .line 17
    .line 18
    new-array v3, v1, [Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p0, Ljj0/f;

    .line 21
    .line 22
    const v4, 0x7f1202bc

    .line 23
    .line 24
    .line 25
    invoke-virtual {p0, v4, v3}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object v3

    .line 29
    const v4, 0x7f12038c

    .line 30
    .line 31
    .line 32
    new-array v1, v1, [Ljava/lang/Object;

    .line 33
    .line 34
    invoke-virtual {p0, v4, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    const/4 v4, 0x0

    .line 39
    const/16 v5, 0x70

    .line 40
    .line 41
    move-object v1, v2

    .line 42
    move-object v2, v3

    .line 43
    move-object v3, p0

    .line 44
    invoke-static/range {v0 .. v5}, Ljp/rf;->a(Lij0/a;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Lql0/g;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0
.end method
