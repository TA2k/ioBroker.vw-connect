.class public final synthetic Lcom/google/android/material/timepicker/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lcom/google/android/material/timepicker/g;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lcom/google/android/material/timepicker/g;->e:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 1

    .line 1
    iget v0, p0, Lcom/google/android/material/timepicker/g;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lcom/google/android/material/timepicker/g;->e:Ljava/lang/Object;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p0, Lcom/google/android/material/timepicker/k;

    .line 9
    .line 10
    invoke-virtual {p0}, Lcom/google/android/material/timepicker/k;->j()V

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    :pswitch_0
    check-cast p0, Lcom/google/android/material/timepicker/i;

    .line 15
    .line 16
    iget-object p0, p0, Lcom/google/android/material/timepicker/i;->B:Ljava/lang/Object;

    .line 17
    .line 18
    instance-of v0, p0, Lcom/google/android/material/timepicker/t;

    .line 19
    .line 20
    if-eqz v0, :cond_0

    .line 21
    .line 22
    check-cast p0, Lcom/google/android/material/timepicker/t;

    .line 23
    .line 24
    invoke-virtual {p0}, Lcom/google/android/material/timepicker/t;->d()V

    .line 25
    .line 26
    .line 27
    :cond_0
    return-void

    .line 28
    nop

    .line 29
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
