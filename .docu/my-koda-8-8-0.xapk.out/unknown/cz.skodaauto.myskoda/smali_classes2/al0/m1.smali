.class public final Lal0/m1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lal0/a0;


# direct methods
.method public constructor <init>(Lal0/a0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lal0/m1;->a:Lal0/a0;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lbl0/j0;)V
    .locals 6

    .line 1
    new-instance v0, Lne0/c;

    .line 2
    .line 3
    new-instance v1, Lbl0/k;

    .line 4
    .line 5
    invoke-direct {v1}, Lbl0/k;-><init>()V

    .line 6
    .line 7
    .line 8
    const/4 v4, 0x0

    .line 9
    const/16 v5, 0x1e

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    const/4 v3, 0x0

    .line 13
    invoke-direct/range {v0 .. v5}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 14
    .line 15
    .line 16
    iget-object p0, p0, Lal0/m1;->a:Lal0/a0;

    .line 17
    .line 18
    check-cast p0, Lyk0/b;

    .line 19
    .line 20
    invoke-virtual {p0, v0}, Lyk0/b;->b(Lne0/s;)V

    .line 21
    .line 22
    .line 23
    iget-object p0, p0, Lyk0/b;->a:Lyy0/c2;

    .line 24
    .line 25
    invoke-virtual {p0, p1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
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
    check-cast v1, Lbl0/j0;

    .line 5
    .line 6
    invoke-virtual {p0, v1}, Lal0/m1;->a(Lbl0/j0;)V

    .line 7
    .line 8
    .line 9
    return-object v0
.end method
