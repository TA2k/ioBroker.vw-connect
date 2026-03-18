.class public final synthetic Lqf/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Lyj/b;

.field public final synthetic g:Lxh/e;

.field public final synthetic h:Ll2/b1;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Lyj/b;Lxh/e;Ll2/b1;I)V
    .locals 0

    .line 1
    iput p5, p0, Lqf/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lqf/a;->e:Ljava/lang/String;

    .line 4
    .line 5
    iput-object p2, p0, Lqf/a;->f:Lyj/b;

    .line 6
    .line 7
    iput-object p3, p0, Lqf/a;->g:Lxh/e;

    .line 8
    .line 9
    iput-object p4, p0, Lqf/a;->h:Ll2/b1;

    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    iget v0, p0, Lqf/a;->d:I

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
    iget-object p1, p0, Lqf/a;->h:Ll2/b1;

    .line 23
    .line 24
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    move-object v1, p1

    .line 29
    check-cast v1, Ljava/lang/String;

    .line 30
    .line 31
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    const/4 v5, 0x0

    .line 35
    iget-object v0, p0, Lqf/a;->e:Ljava/lang/String;

    .line 36
    .line 37
    iget-object v2, p0, Lqf/a;->f:Lyj/b;

    .line 38
    .line 39
    iget-object v3, p0, Lqf/a;->g:Lxh/e;

    .line 40
    .line 41
    invoke-static/range {v0 .. v5}, Lkp/w7;->a(Ljava/lang/String;Ljava/lang/String;Lyj/b;Lxh/e;Ll2/o;I)V

    .line 42
    .line 43
    .line 44
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 45
    .line 46
    return-object p0

    .line 47
    :pswitch_0
    const-string v0, "it"

    .line 48
    .line 49
    invoke-static {p4, p1, p3, p2, v0}, Lz9/c;->c(Ljava/lang/Integer;Lb1/n;Ljava/lang/String;Lz9/k;Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    iget-object p1, p0, Lqf/a;->h:Ll2/b1;

    .line 53
    .line 54
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object p1

    .line 58
    move-object v1, p1

    .line 59
    check-cast v1, Ljava/lang/String;

    .line 60
    .line 61
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    const/4 v5, 0x0

    .line 65
    iget-object v0, p0, Lqf/a;->e:Ljava/lang/String;

    .line 66
    .line 67
    iget-object v2, p0, Lqf/a;->f:Lyj/b;

    .line 68
    .line 69
    iget-object v3, p0, Lqf/a;->g:Lxh/e;

    .line 70
    .line 71
    invoke-static/range {v0 .. v5}, Llp/lb;->a(Ljava/lang/String;Ljava/lang/String;Lyj/b;Lxh/e;Ll2/o;I)V

    .line 72
    .line 73
    .line 74
    goto :goto_0

    .line 75
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
