.class public final synthetic Lz70/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/view/View$OnClickListener;


# instance fields
.field public final synthetic d:Lcom/google/android/material/timepicker/i;

.field public final synthetic e:Ljava/time/LocalDate;

.field public final synthetic f:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Lcom/google/android/material/timepicker/i;Ljava/time/LocalDate;Lay0/k;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lz70/g;->d:Lcom/google/android/material/timepicker/i;

    .line 5
    .line 6
    iput-object p2, p0, Lz70/g;->e:Ljava/time/LocalDate;

    .line 7
    .line 8
    iput-object p3, p0, Lz70/g;->f:Lay0/k;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final onClick(Landroid/view/View;)V
    .locals 2

    .line 1
    iget-object p1, p0, Lz70/g;->d:Lcom/google/android/material/timepicker/i;

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
    invoke-static {}, Ljava/time/OffsetDateTime;->now()Ljava/time/OffsetDateTime;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    invoke-virtual {v0}, Ljava/time/OffsetDateTime;->getOffset()Ljava/time/ZoneOffset;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    iget-object v1, p0, Lz70/g;->e:Ljava/time/LocalDate;

    .line 24
    .line 25
    invoke-static {v1, p1, v0}, Ljava/time/OffsetDateTime;->of(Ljava/time/LocalDate;Ljava/time/LocalTime;Ljava/time/ZoneOffset;)Ljava/time/OffsetDateTime;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    iget-object p0, p0, Lz70/g;->f:Lay0/k;

    .line 33
    .line 34
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    return-void
.end method
