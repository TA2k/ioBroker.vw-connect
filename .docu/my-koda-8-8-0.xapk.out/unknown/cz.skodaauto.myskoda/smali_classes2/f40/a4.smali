.class public final Lf40/a4;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lf40/c1;


# direct methods
.method public constructor <init>(Lf40/c1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lf40/a4;->a:Lf40/c1;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lne0/c;)V
    .locals 1

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lf40/a4;->a:Lf40/c1;

    .line 7
    .line 8
    check-cast p0, Ld40/e;

    .line 9
    .line 10
    iget-object p0, p0, Ld40/e;->a:Lyy0/q1;

    .line 11
    .line 12
    invoke-virtual {p0, p1}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Lne0/c;

    .line 5
    .line 6
    invoke-virtual {p0, v1}, Lf40/a4;->a(Lne0/c;)V

    .line 7
    .line 8
    .line 9
    return-object v0
.end method
