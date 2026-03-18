.class public final synthetic Lmg/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lxh/e;

.field public final synthetic f:Ly1/i;

.field public final synthetic g:Ll2/b1;


# direct methods
.method public synthetic constructor <init>(Lxh/e;Ly1/i;Ll2/b1;I)V
    .locals 0

    .line 1
    iput p4, p0, Lmg/h;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lmg/h;->e:Lxh/e;

    .line 4
    .line 5
    iput-object p2, p0, Lmg/h;->f:Ly1/i;

    .line 6
    .line 7
    iput-object p3, p0, Lmg/h;->g:Ll2/b1;

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    iget v0, p0, Lmg/h;->d:I

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
    iget-object p1, p0, Lmg/h;->g:Ll2/b1;

    .line 25
    .line 26
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    check-cast p1, Lmg/c;

    .line 31
    .line 32
    iget-object v1, p1, Lmg/c;->f:Lac/e;

    .line 33
    .line 34
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    const/4 v5, 0x6

    .line 38
    iget-object v2, p0, Lmg/h;->e:Lxh/e;

    .line 39
    .line 40
    iget-object v3, p0, Lmg/h;->f:Ly1/i;

    .line 41
    .line 42
    invoke-static/range {v0 .. v5}, Lmc/s;->a(Lmc/r;Lac/e;Lay0/k;Lay0/a;Ll2/o;I)V

    .line 43
    .line 44
    .line 45
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 46
    .line 47
    return-object p0

    .line 48
    :pswitch_0
    const-string v0, "it"

    .line 49
    .line 50
    invoke-static {p4, p1, p3, p2, v0}, Lz9/c;->c(Ljava/lang/Integer;Lb1/n;Ljava/lang/String;Lz9/k;Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    sget-object v0, Lmc/r;->d:Lmc/r;

    .line 54
    .line 55
    iget-object p1, p0, Lmg/h;->g:Ll2/b1;

    .line 56
    .line 57
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p1

    .line 61
    check-cast p1, Lmg/c;

    .line 62
    .line 63
    iget-object v1, p1, Lmg/c;->f:Lac/e;

    .line 64
    .line 65
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    const/4 v5, 0x6

    .line 69
    iget-object v2, p0, Lmg/h;->e:Lxh/e;

    .line 70
    .line 71
    iget-object v3, p0, Lmg/h;->f:Ly1/i;

    .line 72
    .line 73
    invoke-static/range {v0 .. v5}, Lmc/s;->a(Lmc/r;Lac/e;Lay0/k;Lay0/a;Ll2/o;I)V

    .line 74
    .line 75
    .line 76
    goto :goto_0

    .line 77
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
