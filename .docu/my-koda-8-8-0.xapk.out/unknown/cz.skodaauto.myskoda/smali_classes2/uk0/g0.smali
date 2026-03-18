.class public final Luk0/g0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Luk0/s0;

.field public final b:Luk0/w;


# direct methods
.method public constructor <init>(Luk0/s0;Luk0/w;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Luk0/g0;->a:Luk0/s0;

    .line 5
    .line 6
    iput-object p2, p0, Luk0/g0;->b:Luk0/w;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Lvk0/j0;)V
    .locals 2

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Luk0/g0;->a:Luk0/s0;

    .line 7
    .line 8
    check-cast v0, Lsk0/c;

    .line 9
    .line 10
    iget-object v0, v0, Lsk0/c;->a:Lyy0/c2;

    .line 11
    .line 12
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 13
    .line 14
    .line 15
    const/4 v1, 0x0

    .line 16
    invoke-virtual {v0, v1, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    iget-object p0, p0, Luk0/g0;->b:Luk0/w;

    .line 20
    .line 21
    check-cast p0, Liy/b;

    .line 22
    .line 23
    sget-object p1, Lly/b;->g2:Lly/b;

    .line 24
    .line 25
    invoke-interface {p0, p1}, Ltl0/a;->a(Lul0/f;)V

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
    check-cast v1, Lvk0/j0;

    .line 5
    .line 6
    invoke-virtual {p0, v1}, Luk0/g0;->a(Lvk0/j0;)V

    .line 7
    .line 8
    .line 9
    return-object v0
.end method
