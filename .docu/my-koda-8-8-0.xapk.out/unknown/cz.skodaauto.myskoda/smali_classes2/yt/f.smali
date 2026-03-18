.class public final synthetic Lyt/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lyt/h;

.field public final synthetic f:Lau/i;

.field public final synthetic g:Lcom/google/protobuf/p;


# direct methods
.method public synthetic constructor <init>(Lyt/h;Lcom/google/protobuf/p;Lau/i;I)V
    .locals 0

    .line 1
    iput p4, p0, Lyt/f;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lyt/f;->e:Lyt/h;

    .line 4
    .line 5
    iput-object p2, p0, Lyt/f;->g:Lcom/google/protobuf/p;

    .line 6
    .line 7
    iput-object p3, p0, Lyt/f;->f:Lau/i;

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 4

    .line 1
    iget v0, p0, Lyt/f;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lyt/f;->g:Lcom/google/protobuf/p;

    .line 7
    .line 8
    check-cast v0, Lau/a0;

    .line 9
    .line 10
    invoke-static {}, Lau/t;->y()Lau/s;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    invoke-virtual {v1}, Lcom/google/protobuf/n;->j()V

    .line 15
    .line 16
    .line 17
    iget-object v2, v1, Lcom/google/protobuf/n;->e:Lcom/google/protobuf/p;

    .line 18
    .line 19
    check-cast v2, Lau/t;

    .line 20
    .line 21
    invoke-static {v2, v0}, Lau/t;->u(Lau/t;Lau/a0;)V

    .line 22
    .line 23
    .line 24
    iget-object v0, p0, Lyt/f;->e:Lyt/h;

    .line 25
    .line 26
    iget-object p0, p0, Lyt/f;->f:Lau/i;

    .line 27
    .line 28
    invoke-virtual {v0, v1, p0}, Lyt/h;->d(Lau/s;Lau/i;)V

    .line 29
    .line 30
    .line 31
    return-void

    .line 32
    :pswitch_0
    iget-object v0, p0, Lyt/f;->g:Lcom/google/protobuf/p;

    .line 33
    .line 34
    check-cast v0, Lau/r;

    .line 35
    .line 36
    iget-object v1, p0, Lyt/f;->e:Lyt/h;

    .line 37
    .line 38
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 39
    .line 40
    .line 41
    invoke-static {}, Lau/t;->y()Lau/s;

    .line 42
    .line 43
    .line 44
    move-result-object v2

    .line 45
    invoke-virtual {v2}, Lcom/google/protobuf/n;->j()V

    .line 46
    .line 47
    .line 48
    iget-object v3, v2, Lcom/google/protobuf/n;->e:Lcom/google/protobuf/p;

    .line 49
    .line 50
    check-cast v3, Lau/t;

    .line 51
    .line 52
    invoke-static {v3, v0}, Lau/t;->v(Lau/t;Lau/r;)V

    .line 53
    .line 54
    .line 55
    iget-object p0, p0, Lyt/f;->f:Lau/i;

    .line 56
    .line 57
    invoke-virtual {v1, v2, p0}, Lyt/h;->d(Lau/s;Lau/i;)V

    .line 58
    .line 59
    .line 60
    return-void

    .line 61
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
