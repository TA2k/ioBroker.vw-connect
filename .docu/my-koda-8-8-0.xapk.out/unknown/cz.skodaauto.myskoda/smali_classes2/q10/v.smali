.class public final Lq10/v;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lq10/f;


# direct methods
.method public constructor <init>(Lq10/f;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lq10/v;->a:Lq10/f;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lr10/b;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lq10/v;->a:Lq10/f;

    .line 2
    .line 3
    check-cast p0, Lo10/t;

    .line 4
    .line 5
    iget-object p0, p0, Lo10/t;->i:Lyy0/c2;

    .line 6
    .line 7
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    const/4 v0, 0x0

    .line 11
    invoke-virtual {p0, v0, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
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
    check-cast v1, Lr10/b;

    .line 5
    .line 6
    invoke-virtual {p0, v1}, Lq10/v;->a(Lr10/b;)V

    .line 7
    .line 8
    .line 9
    return-object v0
.end method
