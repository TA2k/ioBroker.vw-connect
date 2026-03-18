.class public final synthetic Lzb/v;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Llx0/e;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Llx0/e;II)V
    .locals 0

    .line 1
    iput p6, p0, Lzb/v;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lzb/v;->f:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p2, p0, Lzb/v;->g:Ljava/lang/Object;

    .line 6
    .line 7
    iput-object p3, p0, Lzb/v;->h:Ljava/lang/Object;

    .line 8
    .line 9
    iput-object p4, p0, Lzb/v;->i:Llx0/e;

    .line 10
    .line 11
    iput p5, p0, Lzb/v;->e:I

    .line 12
    .line 13
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 14
    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget v0, p0, Lzb/v;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lzb/v;->f:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v1, v0

    .line 9
    check-cast v1, Lqu/c;

    .line 10
    .line 11
    iget-object v0, p0, Lzb/v;->g:Ljava/lang/Object;

    .line 12
    .line 13
    move-object v2, v0

    .line 14
    check-cast v2, Luu/g;

    .line 15
    .line 16
    iget-object v0, p0, Lzb/v;->h:Ljava/lang/Object;

    .line 17
    .line 18
    move-object v3, v0

    .line 19
    check-cast v3, Ljava/util/List;

    .line 20
    .line 21
    iget-object v0, p0, Lzb/v;->i:Llx0/e;

    .line 22
    .line 23
    move-object v4, v0

    .line 24
    check-cast v4, Lay0/k;

    .line 25
    .line 26
    move-object v5, p1

    .line 27
    check-cast v5, Ll2/o;

    .line 28
    .line 29
    check-cast p2, Ljava/lang/Integer;

    .line 30
    .line 31
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 32
    .line 33
    .line 34
    iget p0, p0, Lzb/v;->e:I

    .line 35
    .line 36
    or-int/lit8 p0, p0, 0x1

    .line 37
    .line 38
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 39
    .line 40
    .line 41
    move-result v6

    .line 42
    invoke-static/range {v1 .. v6}, Lzj0/j;->d(Lqu/c;Luu/g;Ljava/util/List;Lay0/k;Ll2/o;I)V

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
    iget-object v0, p0, Lzb/v;->f:Ljava/lang/Object;

    .line 49
    .line 50
    move-object v1, v0

    .line 51
    check-cast v1, Lzb/g;

    .line 52
    .line 53
    iget-object v0, p0, Lzb/v;->g:Ljava/lang/Object;

    .line 54
    .line 55
    move-object v2, v0

    .line 56
    check-cast v2, Ljava/util/Locale;

    .line 57
    .line 58
    iget-object v0, p0, Lzb/v;->h:Ljava/lang/Object;

    .line 59
    .line 60
    move-object v3, v0

    .line 61
    check-cast v3, Ljava/lang/Boolean;

    .line 62
    .line 63
    iget-object v0, p0, Lzb/v;->i:Llx0/e;

    .line 64
    .line 65
    move-object v4, v0

    .line 66
    check-cast v4, Lt2/b;

    .line 67
    .line 68
    move-object v5, p1

    .line 69
    check-cast v5, Ll2/o;

    .line 70
    .line 71
    check-cast p2, Ljava/lang/Integer;

    .line 72
    .line 73
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 74
    .line 75
    .line 76
    iget p0, p0, Lzb/v;->e:I

    .line 77
    .line 78
    or-int/lit8 p0, p0, 0x1

    .line 79
    .line 80
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 81
    .line 82
    .line 83
    move-result v6

    .line 84
    invoke-static/range {v1 .. v6}, Lzb/x;->b(Lzb/g;Ljava/util/Locale;Ljava/lang/Boolean;Lt2/b;Ll2/o;I)V

    .line 85
    .line 86
    .line 87
    goto :goto_0

    .line 88
    nop

    .line 89
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
