.class public final Lkf0/e0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lkf0/z;

.field public final b:Lkf0/o;

.field public final c:Lif0/f0;


# direct methods
.method public constructor <init>(Lkf0/z;Lkf0/o;Lif0/f0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lkf0/e0;->a:Lkf0/z;

    .line 5
    .line 6
    iput-object p2, p0, Lkf0/e0;->b:Lkf0/o;

    .line 7
    .line 8
    iput-object p3, p0, Lkf0/e0;->c:Lif0/f0;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a(Lss0/e;)Lne0/k;
    .locals 3

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lkf0/e0;->a:Lkf0/z;

    .line 7
    .line 8
    invoke-virtual {v0}, Lkf0/z;->invoke()Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    check-cast v0, Lyy0/i;

    .line 13
    .line 14
    new-instance v1, Lac/l;

    .line 15
    .line 16
    const/16 v2, 0x17

    .line 17
    .line 18
    invoke-direct {v1, v2, v0, p0}, Lac/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    new-instance p0, Li40/e1;

    .line 22
    .line 23
    const/16 v0, 0x13

    .line 24
    .line 25
    invoke-direct {p0, p1, v0}, Li40/e1;-><init>(Ljava/lang/Object;I)V

    .line 26
    .line 27
    .line 28
    invoke-static {v1, p0}, Lbb/j0;->b(Lyy0/i;Lay0/k;)Lne0/k;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Lss0/e;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Lkf0/e0;->a(Lss0/e;)Lne0/k;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
