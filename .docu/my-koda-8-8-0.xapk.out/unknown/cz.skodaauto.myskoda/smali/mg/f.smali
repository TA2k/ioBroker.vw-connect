.class public final synthetic Lmg/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ll2/b1;

.field public final synthetic f:Lyj/b;

.field public final synthetic g:Lxh/e;

.field public final synthetic h:Lh2/d6;


# direct methods
.method public synthetic constructor <init>(Ll2/b1;Lyj/b;Lxh/e;Lh2/d6;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Lmg/f;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lmg/f;->e:Ll2/b1;

    iput-object p2, p0, Lmg/f;->f:Lyj/b;

    iput-object p3, p0, Lmg/f;->g:Lxh/e;

    iput-object p4, p0, Lmg/f;->h:Lh2/d6;

    return-void
.end method

.method public synthetic constructor <init>(Lyj/b;Lxh/e;Lh2/d6;Ll2/b1;)V
    .locals 1

    .line 2
    const/4 v0, 0x0

    iput v0, p0, Lmg/f;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lmg/f;->f:Lyj/b;

    iput-object p2, p0, Lmg/f;->g:Lxh/e;

    iput-object p3, p0, Lmg/f;->h:Lh2/d6;

    iput-object p4, p0, Lmg/f;->e:Ll2/b1;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    iget v0, p0, Lmg/f;->d:I

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
    iget-object p1, p0, Lmg/f;->e:Ll2/b1;

    .line 23
    .line 24
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    check-cast p1, Lmg/c;

    .line 29
    .line 30
    iget-object v0, p1, Lmg/c;->e:Lkg/p0;

    .line 31
    .line 32
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    const/4 v5, 0x0

    .line 36
    iget-object v1, p0, Lmg/f;->f:Lyj/b;

    .line 37
    .line 38
    iget-object v2, p0, Lmg/f;->g:Lxh/e;

    .line 39
    .line 40
    iget-object v3, p0, Lmg/f;->h:Lh2/d6;

    .line 41
    .line 42
    invoke-static/range {v0 .. v5}, Lkp/d0;->a(Lkg/p0;Lyj/b;Lxh/e;Lh2/d6;Ll2/o;I)V

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
    iget-object p1, p0, Lmg/f;->e:Ll2/b1;

    .line 54
    .line 55
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    check-cast p1, Lmg/c;

    .line 60
    .line 61
    iget-object v0, p1, Lmg/c;->e:Lkg/p0;

    .line 62
    .line 63
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    const/4 v5, 0x0

    .line 67
    iget-object v1, p0, Lmg/f;->f:Lyj/b;

    .line 68
    .line 69
    iget-object v2, p0, Lmg/f;->g:Lxh/e;

    .line 70
    .line 71
    iget-object v3, p0, Lmg/f;->h:Lh2/d6;

    .line 72
    .line 73
    invoke-static/range {v0 .. v5}, Lkp/d0;->a(Lkg/p0;Lyj/b;Lxh/e;Lh2/d6;Ll2/o;I)V

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
