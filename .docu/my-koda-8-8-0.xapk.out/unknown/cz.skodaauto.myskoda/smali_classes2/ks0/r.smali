.class public final Lks0/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lks0/o;

.field public final b:Lks0/l;


# direct methods
.method public constructor <init>(Lks0/o;Lks0/l;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lks0/r;->a:Lks0/o;

    .line 5
    .line 6
    iput-object p2, p0, Lks0/r;->b:Lks0/l;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Lyb0/h;)Lyy0/i;
    .locals 2

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lks0/r;->a:Lks0/o;

    .line 7
    .line 8
    invoke-virtual {v0, p1}, Lks0/o;->a(Lyb0/h;)Lyy0/i;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    iget-object p0, p0, Lks0/r;->b:Lks0/l;

    .line 13
    .line 14
    invoke-virtual {p0, p1}, Lks0/l;->a(Lyb0/h;)Lyy0/i;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    const/4 p1, 0x2

    .line 19
    new-array p1, p1, [Lyy0/i;

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    aput-object v0, p1, v1

    .line 23
    .line 24
    const/4 v0, 0x1

    .line 25
    aput-object p0, p1, v0

    .line 26
    .line 27
    invoke-static {p1}, Lyy0/u;->D([Lyy0/i;)Lyy0/e;

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
    check-cast v0, Lyb0/h;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Lks0/r;->a(Lyb0/h;)Lyy0/i;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
