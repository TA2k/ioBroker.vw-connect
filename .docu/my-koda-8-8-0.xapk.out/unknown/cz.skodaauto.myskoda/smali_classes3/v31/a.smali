.class public final synthetic Lv31/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lv31/b;

.field public final synthetic f:Lv31/d;


# direct methods
.method public synthetic constructor <init>(Lv31/b;Lv31/d;I)V
    .locals 0

    .line 1
    iput p3, p0, Lv31/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lv31/a;->e:Lv31/b;

    .line 4
    .line 5
    iput-object p2, p0, Lv31/a;->f:Lv31/d;

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
    .locals 4

    .line 1
    iget v0, p0, Lv31/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Li31/d0;

    .line 7
    .line 8
    iget-object v0, p0, Lv31/a;->f:Lv31/d;

    .line 9
    .line 10
    iget-object v1, v0, Lv31/d;->a:Lz21/c;

    .line 11
    .line 12
    iget-object v2, v0, Lv31/d;->e:Lz21/e;

    .line 13
    .line 14
    iget-boolean p1, p1, Li31/d0;->c:Z

    .line 15
    .line 16
    iget-object p0, p0, Lv31/a;->e:Lv31/b;

    .line 17
    .line 18
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 19
    .line 20
    .line 21
    sget-object v3, Lz21/c;->j:Lz21/c;

    .line 22
    .line 23
    if-eq v1, v3, :cond_0

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    iget-object v1, v2, Lz21/e;->a:Lz21/c;

    .line 27
    .line 28
    iget-object v2, v2, Lz21/e;->b:Lz21/c;

    .line 29
    .line 30
    if-eqz p1, :cond_1

    .line 31
    .line 32
    move-object v1, v2

    .line 33
    :cond_1
    :goto_0
    invoke-static {v0, v1}, Lv31/d;->a(Lv31/d;Lz21/c;)Lv31/d;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    invoke-static {p0, p1}, Lv31/b;->b(Lv31/b;Lv31/d;)V

    .line 38
    .line 39
    .line 40
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 41
    .line 42
    return-object p0

    .line 43
    :pswitch_0
    check-cast p1, Ljava/lang/Throwable;

    .line 44
    .line 45
    iget-object p1, p0, Lv31/a;->f:Lv31/d;

    .line 46
    .line 47
    iget-object v0, p1, Lv31/d;->a:Lz21/c;

    .line 48
    .line 49
    iget-object v1, p1, Lv31/d;->e:Lz21/e;

    .line 50
    .line 51
    iget-object p0, p0, Lv31/a;->e:Lv31/b;

    .line 52
    .line 53
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 54
    .line 55
    .line 56
    sget-object v2, Lz21/c;->j:Lz21/c;

    .line 57
    .line 58
    if-eq v0, v2, :cond_2

    .line 59
    .line 60
    goto :goto_2

    .line 61
    :cond_2
    iget-object v0, v1, Lz21/e;->a:Lz21/c;

    .line 62
    .line 63
    :goto_2
    invoke-static {p1, v0}, Lv31/d;->a(Lv31/d;Lz21/c;)Lv31/d;

    .line 64
    .line 65
    .line 66
    move-result-object p1

    .line 67
    invoke-static {p0, p1}, Lv31/b;->b(Lv31/b;Lv31/d;)V

    .line 68
    .line 69
    .line 70
    goto :goto_1

    .line 71
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
