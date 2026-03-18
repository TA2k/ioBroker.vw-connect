.class public final synthetic Lh2/e9;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:Lh2/u7;

.field public final synthetic g:Lgy0/e;


# direct methods
.method public synthetic constructor <init>(ZLh2/u7;Lgy0/e;I)V
    .locals 0

    .line 1
    iput p4, p0, Lh2/e9;->d:I

    .line 2
    .line 3
    iput-boolean p1, p0, Lh2/e9;->e:Z

    .line 4
    .line 5
    iput-object p2, p0, Lh2/e9;->f:Lh2/u7;

    .line 6
    .line 7
    iput-object p3, p0, Lh2/e9;->g:Lgy0/e;

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lh2/e9;->d:I

    .line 2
    .line 3
    check-cast p1, Ld4/l;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-boolean v0, p0, Lh2/e9;->e:Z

    .line 9
    .line 10
    if-nez v0, :cond_0

    .line 11
    .line 12
    invoke-static {p1}, Ld4/x;->a(Ld4/l;)V

    .line 13
    .line 14
    .line 15
    :cond_0
    iget-object v0, p0, Lh2/e9;->f:Lh2/u7;

    .line 16
    .line 17
    iget-object v1, v0, Lh2/u7;->d:Ll2/f1;

    .line 18
    .line 19
    invoke-virtual {v1}, Ll2/f1;->o()F

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    invoke-static {v1}, Lh2/q9;->k(F)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    invoke-static {p1, v1}, Ld4/x;->j(Ld4/l;Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    new-instance v1, Lh2/f9;

    .line 31
    .line 32
    const/4 v2, 0x1

    .line 33
    iget-object p0, p0, Lh2/e9;->g:Lgy0/e;

    .line 34
    .line 35
    invoke-direct {v1, p0, v0, v2}, Lh2/f9;-><init>(Lgy0/e;Lh2/u7;I)V

    .line 36
    .line 37
    .line 38
    invoke-static {p1, v1}, Ld4/x;->g(Ld4/l;Lay0/k;)V

    .line 39
    .line 40
    .line 41
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 42
    .line 43
    return-object p0

    .line 44
    :pswitch_0
    iget-boolean v0, p0, Lh2/e9;->e:Z

    .line 45
    .line 46
    if-nez v0, :cond_1

    .line 47
    .line 48
    invoke-static {p1}, Ld4/x;->a(Ld4/l;)V

    .line 49
    .line 50
    .line 51
    :cond_1
    iget-object v0, p0, Lh2/e9;->f:Lh2/u7;

    .line 52
    .line 53
    iget-object v1, v0, Lh2/u7;->e:Ll2/f1;

    .line 54
    .line 55
    invoke-virtual {v1}, Ll2/f1;->o()F

    .line 56
    .line 57
    .line 58
    move-result v1

    .line 59
    invoke-static {v1}, Lh2/q9;->k(F)Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object v1

    .line 63
    invoke-static {p1, v1}, Ld4/x;->j(Ld4/l;Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    new-instance v1, Lh2/f9;

    .line 67
    .line 68
    const/4 v2, 0x0

    .line 69
    iget-object p0, p0, Lh2/e9;->g:Lgy0/e;

    .line 70
    .line 71
    invoke-direct {v1, p0, v0, v2}, Lh2/f9;-><init>(Lgy0/e;Lh2/u7;I)V

    .line 72
    .line 73
    .line 74
    invoke-static {p1, v1}, Ld4/x;->g(Ld4/l;Lay0/k;)V

    .line 75
    .line 76
    .line 77
    goto :goto_0

    .line 78
    nop

    .line 79
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
