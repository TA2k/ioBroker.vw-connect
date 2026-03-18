.class public final Lks0/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lyb0/l;

.field public final b:Lks0/c;


# direct methods
.method public constructor <init>(Lyb0/l;Lks0/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lks0/l;->a:Lyb0/l;

    .line 5
    .line 6
    iput-object p2, p0, Lks0/l;->b:Lks0/c;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Lyb0/h;)Lyy0/i;
    .locals 7

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v1, Lyb0/i;

    .line 7
    .line 8
    sget-object v2, Lzb0/d;->f:Lzb0/d;

    .line 9
    .line 10
    const/4 v4, 0x0

    .line 11
    const/16 v6, 0x34

    .line 12
    .line 13
    const-string v3, "guest-user-nomination"

    .line 14
    .line 15
    move-object v5, p1

    .line 16
    invoke-direct/range {v1 .. v6}, Lyb0/i;-><init>(Lzb0/d;Ljava/lang/String;Ljava/util/Set;Lyb0/h;I)V

    .line 17
    .line 18
    .line 19
    iget-object p1, p0, Lks0/l;->a:Lyb0/l;

    .line 20
    .line 21
    invoke-virtual {p1, v1}, Lyb0/l;->a(Lyb0/i;)Lzy0/j;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    new-instance v0, Lac/l;

    .line 26
    .line 27
    const/16 v1, 0x18

    .line 28
    .line 29
    invoke-direct {v0, v1, p1, p0}, Lac/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    new-instance p0, Lam0/i;

    .line 33
    .line 34
    const/16 p1, 0xd

    .line 35
    .line 36
    invoke-direct {p0, v0, p1}, Lam0/i;-><init>(Ljava/lang/Object;I)V

    .line 37
    .line 38
    .line 39
    return-object p0
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Lyb0/h;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Lks0/l;->a(Lyb0/h;)Lyy0/i;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
