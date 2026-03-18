.class public final Le10/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lc10/b;

.field public final b:Le10/c;


# direct methods
.method public constructor <init>(Lc10/b;Le10/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Le10/b;->a:Lc10/b;

    .line 5
    .line 6
    iput-object p2, p0, Le10/b;->b:Le10/c;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/String;)Lyy0/i;
    .locals 5

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Le10/b;->a:Lc10/b;

    .line 7
    .line 8
    iget-object v1, v0, Lc10/b;->a:Lxl0/f;

    .line 9
    .line 10
    new-instance v2, La2/c;

    .line 11
    .line 12
    const/4 v3, 0x5

    .line 13
    const/4 v4, 0x0

    .line 14
    invoke-direct {v2, v3, v0, p1, v4}, La2/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 15
    .line 16
    .line 17
    new-instance p1, Lc1/c2;

    .line 18
    .line 19
    const/16 v0, 0xf

    .line 20
    .line 21
    invoke-direct {p1, v0}, Lc1/c2;-><init>(I)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {v1, v2, p1, v4}, Lxl0/f;->e(Lay0/k;Lay0/k;Lay0/k;)Lyy0/m1;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    new-instance v0, La60/f;

    .line 29
    .line 30
    const/16 v1, 0x1d

    .line 31
    .line 32
    invoke-direct {v0, p0, v4, v1}, La60/f;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 33
    .line 34
    .line 35
    new-instance p0, Lne0/n;

    .line 36
    .line 37
    const/4 v1, 0x5

    .line 38
    invoke-direct {p0, p1, v0, v1}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 39
    .line 40
    .line 41
    return-object p0
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Ljava/lang/String;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Le10/b;->a(Ljava/lang/String;)Lyy0/i;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
