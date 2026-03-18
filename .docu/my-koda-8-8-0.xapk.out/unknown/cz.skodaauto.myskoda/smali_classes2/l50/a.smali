.class public final Ll50/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lj50/f;


# direct methods
.method public constructor <init>(Lj50/f;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ll50/a;->a:Lj50/f;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lbl0/p;)Lyy0/i;
    .locals 3

    .line 1
    iget-object v0, p1, Lbl0/p;->a:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/4 v1, 0x0

    .line 8
    if-nez v0, :cond_0

    .line 9
    .line 10
    new-instance p0, Lne0/e;

    .line 11
    .line 12
    invoke-direct {p0, v1}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    new-instance p1, Lyy0/m;

    .line 16
    .line 17
    const/4 v0, 0x0

    .line 18
    invoke-direct {p1, p0, v0}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 19
    .line 20
    .line 21
    return-object p1

    .line 22
    :cond_0
    iget-object p0, p0, Ll50/a;->a:Lj50/f;

    .line 23
    .line 24
    iget-object v0, p0, Lj50/f;->a:Lxl0/f;

    .line 25
    .line 26
    new-instance v2, Lj50/e;

    .line 27
    .line 28
    invoke-direct {v2, p1, p0, v1}, Lj50/e;-><init>(Lbl0/p;Lj50/f;Lkotlin/coroutines/Continuation;)V

    .line 29
    .line 30
    .line 31
    new-instance p0, Lim0/b;

    .line 32
    .line 33
    const/16 p1, 0xb

    .line 34
    .line 35
    invoke-direct {p0, p1}, Lim0/b;-><init>(I)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {v0, v2, p0, v1}, Lxl0/f;->e(Lay0/k;Lay0/k;Lay0/k;)Lyy0/m1;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    return-object p0
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Lbl0/p;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Ll50/a;->a(Lbl0/p;)Lyy0/i;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
