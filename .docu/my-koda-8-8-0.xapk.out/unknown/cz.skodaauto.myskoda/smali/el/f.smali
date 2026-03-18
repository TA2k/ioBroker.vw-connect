.class public final synthetic Lel/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ll2/b1;

.field public final synthetic f:Lay0/k;

.field public final synthetic g:Ldi/l;


# direct methods
.method public synthetic constructor <init>(Ll2/b1;Lay0/k;Ldi/l;I)V
    .locals 0

    .line 1
    iput p4, p0, Lel/f;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lel/f;->e:Ll2/b1;

    .line 4
    .line 5
    iput-object p2, p0, Lel/f;->f:Lay0/k;

    .line 6
    .line 7
    iput-object p3, p0, Lel/f;->g:Ldi/l;

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lel/f;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 7
    .line 8
    iget-object v1, p0, Lel/f;->e:Ll2/b1;

    .line 9
    .line 10
    invoke-interface {v1, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    new-instance v0, Ldi/e;

    .line 14
    .line 15
    iget-object v1, p0, Lel/f;->g:Ldi/l;

    .line 16
    .line 17
    iget-object v1, v1, Ldi/l;->i:Ljava/lang/String;

    .line 18
    .line 19
    invoke-direct {v0, v1}, Ldi/e;-><init>(Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    iget-object p0, p0, Lel/f;->f:Lay0/k;

    .line 23
    .line 24
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    return-object p0

    .line 30
    :pswitch_0
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 31
    .line 32
    iget-object v1, p0, Lel/f;->e:Ll2/b1;

    .line 33
    .line 34
    invoke-interface {v1, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    new-instance v0, Ldi/e;

    .line 38
    .line 39
    iget-object v1, p0, Lel/f;->g:Ldi/l;

    .line 40
    .line 41
    iget-object v1, v1, Ldi/l;->i:Ljava/lang/String;

    .line 42
    .line 43
    invoke-direct {v0, v1}, Ldi/e;-><init>(Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    iget-object p0, p0, Lel/f;->f:Lay0/k;

    .line 47
    .line 48
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    goto :goto_0

    .line 52
    nop

    .line 53
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
