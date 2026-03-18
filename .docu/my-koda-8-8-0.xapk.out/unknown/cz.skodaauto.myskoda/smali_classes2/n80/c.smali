.class public final synthetic Ln80/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lm80/b;

.field public final synthetic f:Lay0/a;

.field public final synthetic g:Lay0/a;

.field public final synthetic h:Lay0/a;

.field public final synthetic i:Lay0/a;

.field public final synthetic j:Lay0/a;

.field public final synthetic k:I


# direct methods
.method public synthetic constructor <init>(Lm80/b;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;II)V
    .locals 0

    .line 1
    iput p8, p0, Ln80/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ln80/c;->e:Lm80/b;

    .line 4
    .line 5
    iput-object p2, p0, Ln80/c;->f:Lay0/a;

    .line 6
    .line 7
    iput-object p3, p0, Ln80/c;->g:Lay0/a;

    .line 8
    .line 9
    iput-object p4, p0, Ln80/c;->h:Lay0/a;

    .line 10
    .line 11
    iput-object p5, p0, Ln80/c;->i:Lay0/a;

    .line 12
    .line 13
    iput-object p6, p0, Ln80/c;->j:Lay0/a;

    .line 14
    .line 15
    iput p7, p0, Ln80/c;->k:I

    .line 16
    .line 17
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 18
    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Ln80/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    move-object v7, p1

    .line 7
    check-cast v7, Ll2/o;

    .line 8
    .line 9
    check-cast p2, Ljava/lang/Integer;

    .line 10
    .line 11
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    iget p1, p0, Ln80/c;->k:I

    .line 15
    .line 16
    or-int/lit8 p1, p1, 0x1

    .line 17
    .line 18
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 19
    .line 20
    .line 21
    move-result v8

    .line 22
    iget-object v1, p0, Ln80/c;->e:Lm80/b;

    .line 23
    .line 24
    iget-object v2, p0, Ln80/c;->f:Lay0/a;

    .line 25
    .line 26
    iget-object v3, p0, Ln80/c;->g:Lay0/a;

    .line 27
    .line 28
    iget-object v4, p0, Ln80/c;->h:Lay0/a;

    .line 29
    .line 30
    iget-object v5, p0, Ln80/c;->i:Lay0/a;

    .line 31
    .line 32
    iget-object v6, p0, Ln80/c;->j:Lay0/a;

    .line 33
    .line 34
    invoke-static/range {v1 .. v8}, Ln80/a;->b(Lm80/b;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 35
    .line 36
    .line 37
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 38
    .line 39
    return-object p0

    .line 40
    :pswitch_0
    move-object v6, p1

    .line 41
    check-cast v6, Ll2/o;

    .line 42
    .line 43
    check-cast p2, Ljava/lang/Integer;

    .line 44
    .line 45
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 46
    .line 47
    .line 48
    iget p1, p0, Ln80/c;->k:I

    .line 49
    .line 50
    or-int/lit8 p1, p1, 0x1

    .line 51
    .line 52
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 53
    .line 54
    .line 55
    move-result v7

    .line 56
    iget-object v0, p0, Ln80/c;->e:Lm80/b;

    .line 57
    .line 58
    iget-object v1, p0, Ln80/c;->f:Lay0/a;

    .line 59
    .line 60
    iget-object v2, p0, Ln80/c;->g:Lay0/a;

    .line 61
    .line 62
    iget-object v3, p0, Ln80/c;->h:Lay0/a;

    .line 63
    .line 64
    iget-object v4, p0, Ln80/c;->i:Lay0/a;

    .line 65
    .line 66
    iget-object v5, p0, Ln80/c;->j:Lay0/a;

    .line 67
    .line 68
    invoke-static/range {v0 .. v7}, Ln80/a;->b(Lm80/b;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 69
    .line 70
    .line 71
    goto :goto_0

    .line 72
    nop

    .line 73
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
