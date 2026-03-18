.class public final synthetic Lo10/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lo10/e;

.field public final synthetic f:Lua/a;


# direct methods
.method public synthetic constructor <init>(Lo10/e;Lua/a;I)V
    .locals 0

    .line 1
    iput p3, p0, Lo10/d;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lo10/d;->e:Lo10/e;

    .line 4
    .line 5
    iput-object p2, p0, Lo10/d;->f:Lua/a;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lo10/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Landroidx/collection/u;

    .line 7
    .line 8
    const-string v0, "_tmpMap"

    .line 9
    .line 10
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object v0, p0, Lo10/d;->e:Lo10/e;

    .line 14
    .line 15
    iget-object p0, p0, Lo10/d;->f:Lua/a;

    .line 16
    .line 17
    invoke-virtual {v0, p0, p1}, Lo10/e;->a(Lua/a;Landroidx/collection/u;)V

    .line 18
    .line 19
    .line 20
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 21
    .line 22
    return-object p0

    .line 23
    :pswitch_0
    check-cast p1, Landroidx/collection/f;

    .line 24
    .line 25
    const-string v0, "_tmpMap"

    .line 26
    .line 27
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    iget-object v0, p0, Lo10/d;->e:Lo10/e;

    .line 31
    .line 32
    iget-object p0, p0, Lo10/d;->f:Lua/a;

    .line 33
    .line 34
    invoke-virtual {v0, p0, p1}, Lo10/e;->b(Lua/a;Landroidx/collection/f;)V

    .line 35
    .line 36
    .line 37
    goto :goto_0

    .line 38
    nop

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
