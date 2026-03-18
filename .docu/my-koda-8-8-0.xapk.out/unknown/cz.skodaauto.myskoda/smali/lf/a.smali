.class public final synthetic Llf/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lxh/e;

.field public final synthetic f:Ly1/i;


# direct methods
.method public synthetic constructor <init>(Lxh/e;Ly1/i;I)V
    .locals 0

    .line 1
    iput p3, p0, Llf/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Llf/a;->e:Lxh/e;

    .line 4
    .line 5
    iput-object p2, p0, Llf/a;->f:Ly1/i;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    iget v0, p0, Llf/a;->d:I

    .line 2
    .line 3
    check-cast p1, Lb1/n;

    .line 4
    .line 5
    check-cast p2, Lz9/k;

    .line 6
    .line 7
    move-object v4, p3

    .line 8
    check-cast v4, Ll2/o;

    .line 9
    .line 10
    check-cast p4, Ljava/lang/Integer;

    .line 11
    .line 12
    const-string p3, "$this$composable"

    .line 13
    .line 14
    packed-switch v0, :pswitch_data_0

    .line 15
    .line 16
    .line 17
    const-string v0, "it"

    .line 18
    .line 19
    invoke-static {p4, p1, p3, p2, v0}, Lz9/c;->c(Ljava/lang/Integer;Lb1/n;Ljava/lang/String;Lz9/k;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    sget-object v0, Lmc/r;->e:Lmc/r;

    .line 23
    .line 24
    const/4 v1, 0x0

    .line 25
    const/16 v5, 0x36

    .line 26
    .line 27
    iget-object v2, p0, Llf/a;->e:Lxh/e;

    .line 28
    .line 29
    iget-object v3, p0, Llf/a;->f:Ly1/i;

    .line 30
    .line 31
    invoke-static/range {v0 .. v5}, Lmc/s;->a(Lmc/r;Lac/e;Lay0/k;Lay0/a;Ll2/o;I)V

    .line 32
    .line 33
    .line 34
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 35
    .line 36
    return-object p0

    .line 37
    :pswitch_0
    const-string v0, "it"

    .line 38
    .line 39
    invoke-static {p4, p1, p3, p2, v0}, Lz9/c;->c(Ljava/lang/Integer;Lb1/n;Ljava/lang/String;Lz9/k;Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    sget-object v0, Lmc/r;->e:Lmc/r;

    .line 43
    .line 44
    const/4 v1, 0x0

    .line 45
    const/16 v5, 0x36

    .line 46
    .line 47
    iget-object v2, p0, Llf/a;->e:Lxh/e;

    .line 48
    .line 49
    iget-object v3, p0, Llf/a;->f:Ly1/i;

    .line 50
    .line 51
    invoke-static/range {v0 .. v5}, Lmc/s;->a(Lmc/r;Lac/e;Lay0/k;Lay0/a;Ll2/o;I)V

    .line 52
    .line 53
    .line 54
    goto :goto_0

    .line 55
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
