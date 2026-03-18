.class public final Lcom/google/android/material/datepicker/e0;
.super Lka/v0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final u:Landroid/widget/TextView;

.field public final v:Lcom/google/android/material/datepicker/MaterialCalendarGridView;


# direct methods
.method public constructor <init>(Landroid/widget/LinearLayout;Z)V
    .locals 8

    .line 1
    invoke-direct {p0, p1}, Lka/v0;-><init>(Landroid/view/View;)V

    .line 2
    .line 3
    .line 4
    const v0, 0x7f0a0202

    .line 5
    .line 6
    .line 7
    invoke-virtual {p1, v0}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    check-cast v0, Landroid/widget/TextView;

    .line 12
    .line 13
    iput-object v0, p0, Lcom/google/android/material/datepicker/e0;->u:Landroid/widget/TextView;

    .line 14
    .line 15
    sget-object v1, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 16
    .line 17
    new-instance v2, Ld6/f0;

    .line 18
    .line 19
    const/4 v5, 0x0

    .line 20
    const/4 v7, 0x1

    .line 21
    const v3, 0x7f0a02c4

    .line 22
    .line 23
    .line 24
    const-class v4, Ljava/lang/Boolean;

    .line 25
    .line 26
    const/16 v6, 0x1c

    .line 27
    .line 28
    invoke-direct/range {v2 .. v7}, Ld6/f0;-><init>(ILjava/lang/Class;III)V

    .line 29
    .line 30
    .line 31
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 32
    .line 33
    invoke-virtual {v2, v0, v1}, Ld6/h0;->f(Landroid/view/View;Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    const v1, 0x7f0a01fd

    .line 37
    .line 38
    .line 39
    invoke-virtual {p1, v1}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 40
    .line 41
    .line 42
    move-result-object p1

    .line 43
    check-cast p1, Lcom/google/android/material/datepicker/MaterialCalendarGridView;

    .line 44
    .line 45
    iput-object p1, p0, Lcom/google/android/material/datepicker/e0;->v:Lcom/google/android/material/datepicker/MaterialCalendarGridView;

    .line 46
    .line 47
    if-nez p2, :cond_0

    .line 48
    .line 49
    const/16 p0, 0x8

    .line 50
    .line 51
    invoke-virtual {v0, p0}, Landroid/view/View;->setVisibility(I)V

    .line 52
    .line 53
    .line 54
    :cond_0
    return-void
.end method
