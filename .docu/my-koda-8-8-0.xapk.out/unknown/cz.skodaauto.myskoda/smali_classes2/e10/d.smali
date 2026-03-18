.class public final Le10/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Le10/c;

.field public final b:Le10/b;


# direct methods
.method public constructor <init>(Le10/c;Le10/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Le10/d;->a:Le10/c;

    .line 5
    .line 6
    iput-object p2, p0, Le10/d;->b:Le10/b;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/String;)Lyy0/i;
    .locals 6

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Le10/d;->a:Le10/c;

    .line 7
    .line 8
    check-cast v0, Lc10/a;

    .line 9
    .line 10
    iget-object v1, v0, Lc10/a;->d:Lyy0/c2;

    .line 11
    .line 12
    iget-object v0, v0, Lc10/a;->b:Lez0/c;

    .line 13
    .line 14
    new-instance v2, Ld2/g;

    .line 15
    .line 16
    const/4 v3, 0x6

    .line 17
    invoke-direct {v2, p0, v3}, Ld2/g;-><init>(Ljava/lang/Object;I)V

    .line 18
    .line 19
    .line 20
    new-instance v3, Lc1/b;

    .line 21
    .line 22
    const/4 v4, 0x0

    .line 23
    const/4 v5, 0x1

    .line 24
    invoke-direct {v3, v5, p0, p1, v4}, Lc1/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 25
    .line 26
    .line 27
    invoke-static {v1, v0, v2, v3}, Lbb/j0;->h(Lyy0/i;Lez0/a;Lay0/a;Lay0/k;)Lne0/n;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
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
    invoke-virtual {p0, v0}, Le10/d;->a(Ljava/lang/String;)Lyy0/i;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
