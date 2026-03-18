.class public final synthetic Lxf0/r3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/view/View$OnClickListener;


# instance fields
.field public final synthetic d:Lay0/k;

.field public final synthetic e:Lcom/google/android/material/timepicker/i;


# direct methods
.method public synthetic constructor <init>(Lay0/k;Lcom/google/android/material/timepicker/i;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lxf0/r3;->d:Lay0/k;

    .line 5
    .line 6
    iput-object p2, p0, Lxf0/r3;->e:Lcom/google/android/material/timepicker/i;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final onClick(Landroid/view/View;)V
    .locals 1

    .line 1
    iget-object p1, p0, Lxf0/r3;->e:Lcom/google/android/material/timepicker/i;

    .line 2
    .line 3
    iget-object p1, p1, Lcom/google/android/material/timepicker/i;->N:Lcom/google/android/material/timepicker/l;

    .line 4
    .line 5
    iget v0, p1, Lcom/google/android/material/timepicker/l;->g:I

    .line 6
    .line 7
    rem-int/lit8 v0, v0, 0x18

    .line 8
    .line 9
    iget p1, p1, Lcom/google/android/material/timepicker/l;->h:I

    .line 10
    .line 11
    invoke-static {v0, p1}, Ljava/time/LocalTime;->of(II)Ljava/time/LocalTime;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    const-string v0, "of(...)"

    .line 16
    .line 17
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    iget-object p0, p0, Lxf0/r3;->d:Lay0/k;

    .line 21
    .line 22
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    return-void
.end method
