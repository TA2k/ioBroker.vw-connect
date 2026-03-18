.class public final Lq10/u;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lq10/a;

.field public final b:Lq10/f;


# direct methods
.method public constructor <init>(Lq10/a;Lq10/f;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lq10/u;->a:Lq10/a;

    .line 5
    .line 6
    iput-object p2, p0, Lq10/u;->b:Lq10/f;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Lr10/b;

    .line 5
    .line 6
    iget-object v2, p0, Lq10/u;->b:Lq10/f;

    .line 7
    .line 8
    check-cast v2, Lo10/t;

    .line 9
    .line 10
    iget-object v2, v2, Lo10/t;->i:Lyy0/c2;

    .line 11
    .line 12
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 13
    .line 14
    .line 15
    const/4 v3, 0x0

    .line 16
    invoke-virtual {v2, v3, v1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    iget-object p0, p0, Lq10/u;->a:Lq10/a;

    .line 20
    .line 21
    check-cast p0, Liy/b;

    .line 22
    .line 23
    sget-object v1, Lly/b;->X:Lly/b;

    .line 24
    .line 25
    invoke-interface {p0, v1}, Ltl0/a;->a(Lul0/f;)V

    .line 26
    .line 27
    .line 28
    return-object v0
.end method
